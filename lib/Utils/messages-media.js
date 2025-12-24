import { Boom } from '@hapi/boom';
import { exec } from 'child_process';
import * as Crypto from 'crypto';
import { once } from 'events';
import { createReadStream, createWriteStream, promises as fs, WriteStream } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { Readable, Transform } from 'stream';
import { URL } from 'url';
import { proto } from '../../WAProto/index.js';
import { DEFAULT_ORIGIN, MEDIA_HKDF_KEY_MAPPING, MEDIA_PATH_MAP } from '../Defaults/index.js';
import { getBinaryNodeChild, getBinaryNodeChildBuffer, jidNormalizedUser } from '../WABinary/index.js';
import { aesDecryptGCM, aesEncryptGCM, hkdf } from './crypto.js';
import { generateMessageIDV2 } from './generics.js';

const getTmpFilesDirectory = () => tmpdir();

const getImageProcessingLibrary = async () => {
    const [jimp, sharp] = await Promise.all([
        import('jimp').catch(() => { }),
        import('sharp').catch(() => { })
    ]);
    
    if (sharp) {
        return { sharp };
    }
    if (jimp) {
        return { jimp };
    }
    throw new Boom('No image processing library available');
};

export const hkdfInfoKey = (type) => {
    const hkdfInfo = MEDIA_HKDF_KEY_MAPPING[type];
    return `WhatsApp ${hkdfInfo} Keys`;
};

// FIXED: Stream-based upload data preparation
export const getRawMediaUploadData = async (media, mediaType, logger) => {
    const { stream } = await getStream(media);
    logger?.debug('got stream for raw upload');
    
    const hasher = Crypto.createHash('sha256');
    const filePath = join(tmpdir(), mediaType + generateMessageIDV2());
    const fileWriteStream = createWriteStream(filePath);
    
    let fileLength = 0;
    
    try {
        for await (const data of stream) {
            fileLength += data.length;
            hasher.update(data);
            if (!fileWriteStream.write(data)) {
                await once(fileWriteStream, 'drain');
            }
        }
        
        fileWriteStream.end();
        await once(fileWriteStream, 'finish');
        stream.destroy();
        
        const fileSha256 = hasher.digest();
        logger?.debug('hashed data for raw upload');
        
        return {
            filePath: filePath,
            fileSha256,
            fileLength
        };
    } catch (error) {
        fileWriteStream.destroy();
        stream.destroy();
        try {
            await fs.unlink(filePath);
        } catch {
            // ignore cleanup errors
        }
        throw error;
    }
};

/** generates all the keys required to encrypt/decrypt & sign a media message */
export async function getMediaKeys(buffer, mediaType) {
    if (!buffer) {
        throw new Boom('Cannot derive from empty media key');
    }
    
    if (typeof buffer === 'string') {
        buffer = Buffer.from(buffer.replace('data:;base64,', ''), 'base64');
    }
    
    // expand using HKDF to 112 bytes, also pass in the relevant app info
    const expandedMediaKey = await hkdf(buffer, 112, { info: hkdfInfoKey(mediaType) });
    return {
        iv: expandedMediaKey.slice(0, 16),
        cipherKey: expandedMediaKey.slice(16, 48),
        macKey: expandedMediaKey.slice(48, 80)
    };
}

/** Extracts video thumb using FFMPEG */
const extractVideoThumb = async (path, destPath, time, size) => new Promise((resolve, reject) => {
    const cmd = `ffmpeg -ss ${time} -i ${path} -y -vf scale=${size.width}:-1 -vframes 1 -f image2 ${destPath}`;
    exec(cmd, err => {
        if (err) {
            reject(err);
        } else {
            resolve();
        }
    });
});

// FIXED: Stream-based image thumb extraction
export const extractImageThumb = async (bufferOrFilePath, width = 32) => {
    // Handle streams without loading into memory
    let buffer;
    if (bufferOrFilePath instanceof Readable) {
        // For large images, use streaming approach
        const lib = await getImageProcessingLibrary();
        if ('sharp' in lib && typeof lib.sharp?.default === 'function') {
            // sharp can handle streams directly
            const img = lib.sharp.default(bufferOrFilePath);
            const dimensions = await img.metadata();
            const buffer = await img.resize(width).jpeg({ quality: 50 }).toBuffer();
            return {
                buffer,
                original: {
                    width: dimensions.width,
                    height: dimensions.height
                }
            };
        } else {
            // For jimp, we need to buffer but limit size
            buffer = await toBufferWithLimit(bufferOrFilePath, 10 * 1024 * 1024); // 10MB limit
        }
    } else {
        buffer = bufferOrFilePath;
    }
    
    const lib = await getImageProcessingLibrary();
    if ('sharp' in lib && typeof lib.sharp?.default === 'function') {
        const img = lib.sharp.default(buffer);
        const dimensions = await img.metadata();
        const thumbBuffer = await img.resize(width).jpeg({ quality: 50 }).toBuffer();
        return {
            buffer: thumbBuffer,
            original: {
                width: dimensions.width,
                height: dimensions.height
            }
        };
    } else if ('jimp' in lib && typeof lib.jimp?.Jimp === 'object') {
        const jimp = await lib.jimp.Jimp.read(buffer);
        const dimensions = {
            width: jimp.width,
            height: jimp.height
        };
        const thumbBuffer = await jimp
            .resize({ w: width, mode: lib.jimp.ResizeStrategy.BILINEAR })
            .getBuffer('image/jpeg', { quality: 50 });
        return {
            buffer: thumbBuffer,
            original: dimensions
        };
    } else {
        throw new Boom('No image processing library available');
    }
};

// Helper function to limit buffer size
const toBufferWithLimit = async (stream, maxSize) => {
    const chunks = [];
    let totalSize = 0;
    
    for await (const chunk of stream) {
        totalSize += chunk.length;
        if (totalSize > maxSize) {
            stream.destroy();
            throw new Boom(`File too large, max ${maxSize / 1024 / 1024}MB allowed`);
        }
        chunks.push(chunk);
    }
    
    stream.destroy();
    return Buffer.concat(chunks);
};

export const encodeBase64EncodedStringForUpload = (b64) => encodeURIComponent(b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=+$/, ''));

// FIXED: Stream-based profile picture generation
export const generateProfilePicture = async (mediaUpload, dimensions) => {
    let input;
    const { width: w = 640, height: h = 640 } = dimensions || {};
    
    if (Buffer.isBuffer(mediaUpload)) {
        input = mediaUpload;
    } else {
        // Use getStream to handle all WAMediaUpload types
        const { stream } = await getStream(mediaUpload);
        // Use limited buffer for profile pictures
        input = await toBufferWithLimit(stream, 10 * 1024 * 1024); // 10MB limit
    }
    
    const lib = await getImageProcessingLibrary();
    
    if ('sharp' in lib && typeof lib.sharp?.default === 'function') {
        const img = await lib.sharp
            .default(input)
            .resize(w, h)
            .jpeg({
                quality: 50
            })
            .toBuffer();
        return {
            img
        };
    } else if ('jimp' in lib && typeof lib.jimp?.Jimp === 'object') {
        const jimp = await lib.jimp.Jimp.read(input);
        const min = Math.min(jimp.width, jimp.height);
        const cropped = jimp.crop({ x: 0, y: 0, w: min, h: min });
        const img = await cropped.resize({ w, h, mode: lib.jimp.ResizeStrategy.BILINEAR })
            .getBuffer('image/jpeg', { quality: 50 });
        return {
            img
        };
    } else {
        throw new Boom('No image processing library available');
    }
};

/** gets the SHA256 of the given media message */
export const mediaMessageSHA256B64 = (message) => {
    const media = Object.values(message)[0];
    return media?.fileSha256 && Buffer.from(media.fileSha256).toString('base64');
};

// FIXED: Stream-based audio duration
export async function getAudioDuration(buffer) {
    const musicMetadata = await import('music-metadata');
    const options = {
        duration: true,
        skipCovers: true // Skip loading cover art to save memory
    };
    
    if (Buffer.isBuffer(buffer)) {
        // For buffers, use parseBuffer but limit size
        if (buffer.length > 50 * 1024 * 1024) { // 50MB limit
            throw new Boom('Audio file too large for duration extraction');
        }
        const metadata = await musicMetadata.parseBuffer(buffer, undefined, options);
        return metadata.format.duration;
    } else if (typeof buffer === 'string') {
        // For file paths, use streaming
        const metadata = await musicMetadata.parseFile(buffer, options);
        return metadata.format.duration;
    } else {
        // For streams, use streaming parse
        const metadata = await musicMetadata.parseStream(buffer, undefined, options);
        return metadata.format.duration;
    }
}

/**
  referenced from and modifying https://github.com/wppconnect-team/wa-js/blob/main/src/chat/functions/prepareAudioWaveform.ts
 */
export async function getAudioWaveform(buffer, logger) {
    try {
        // @ts-ignore
        const { default: decoder } = await import('audio-decode');
        let audioData;
        
        // FIXED: Stream processing with size limit
        if (Buffer.isBuffer(buffer)) {
            if (buffer.length > 20 * 1024 * 1024) { // 20MB limit for waveform
                logger?.debug('Audio file too large for waveform generation');
                return;
            }
            audioData = buffer;
        } else if (typeof buffer === 'string') {
            const rStream = createReadStream(buffer);
            audioData = await toBufferWithLimit(rStream, 20 * 1024 * 1024); // 20MB limit
        } else {
            audioData = await toBufferWithLimit(buffer, 20 * 1024 * 1024); // 20MB limit
        }
        
        const audioBuffer = await decoder(audioData);
        const rawData = audioBuffer.getChannelData(0);
        const samples = 64;
        const blockSize = Math.floor(rawData.length / samples);
        const filteredData = [];
        
        for (let i = 0; i < samples; i++) {
            const blockStart = blockSize * i;
            let sum = 0;
            for (let j = 0; j < blockSize; j++) {
                sum = sum + Math.abs(rawData[blockStart + j]);
            }
            filteredData.push(sum / blockSize);
        }
        
        const multiplier = Math.pow(Math.max(...filteredData), -1);
        const normalizedData = filteredData.map(n => n * multiplier);
        
        const waveform = new Uint8Array(normalizedData.map(n => Math.floor(100 * n)));
        return waveform;
    } catch (e) {
        logger?.debug('Failed to generate waveform: ' + e);
    }
}

export const toReadable = (buffer) => {
    const readable = new Readable({ read: () => { } });
    readable.push(buffer);
    readable.push(null);
    return readable;
};

// FIXED: Stream to buffer with memory limit
export const toBuffer = async (stream, maxSize = 100 * 1024 * 1024) => { // 100MB default limit
    const chunks = [];
    let totalSize = 0;
    
    for await (const chunk of stream) {
        totalSize += chunk.length;
        if (totalSize > maxSize) {
            stream.destroy();
            throw new Boom(`File too large, max ${maxSize / 1024 / 1024}MB allowed`);
        }
        chunks.push(chunk);
    }
    
    stream.destroy();
    return Buffer.concat(chunks);
};

export const getStream = async (item, opts) => {
    if (Buffer.isBuffer(item)) {
        return { stream: toReadable(item), type: 'buffer' };
    }
    
    if ('stream' in item) {
        return { stream: item.stream, type: 'readable' };
    }
    
    const urlStr = item.url.toString();
    if (urlStr.startsWith('data:')) {
        const buffer = Buffer.from(urlStr.split(',')[1], 'base64');
        return { stream: toReadable(buffer), type: 'buffer' };
    }
    
    if (urlStr.startsWith('http://') || urlStr.startsWith('https://')) {
        return { stream: await getHttpStream(item.url, opts), type: 'remote' };
    }
    
    return { stream: createReadStream(item.url), type: 'file' };
};

/** generates a thumbnail for a given media, if required */
export async function generateThumbnail(file, mediaType, options) {
    let thumbnail;
    let originalImageDimensions;
    
    if (mediaType === 'image') {
        try {
            const { buffer, original } = await extractImageThumb(file);
            thumbnail = buffer.toString('base64');
            if (original.width && original.height) {
                originalImageDimensions = {
                    width: original.width,
                    height: original.height
                };
            }
        } catch (err) {
            options.logger?.debug('could not generate image thumb: ' + err);
        }
    } else if (mediaType === 'video') {
        const imgFilename = join(getTmpFilesDirectory(), generateMessageIDV2() + '.jpg');
        try {
            await extractVideoThumb(file, imgFilename, '00:00:00', { width: 32, height: 32 });
            const buff = await fs.readFile(imgFilename);
            thumbnail = buff.toString('base64');
            await fs.unlink(imgFilename);
        } catch (err) {
            options.logger?.debug('could not generate video thumb: ' + err);
        }
    }
    
    return {
        thumbnail,
        originalImageDimensions
    };
}

export const getHttpStream = async (url, options = {}) => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
    
    try {
        const response = await fetch(url.toString(), {
            dispatcher: options.dispatcher,
            method: 'GET',
            headers: options.headers,
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (!response.ok) {
            throw new Boom(`Failed to fetch stream from ${url}`, { 
                statusCode: response.status, 
                data: { url } 
            });
        }
        
        // @ts-ignore Node18+ Readable.fromWeb exists
        return Readable.fromWeb(response.body);
    } catch (error) {
        clearTimeout(timeoutId);
        throw error;
    }
};

// FIXED: Stream-based encryption without loading entire file
export const encryptedStream = async (media, mediaType, { logger, saveOriginalFileIfRequired, opts } = {}) => {
    const { stream, type } = await getStream(media, opts);
    logger?.debug('fetched media stream');
    
    const mediaKey = Crypto.randomBytes(32);
    const { cipherKey, iv, macKey } = await getMediaKeys(mediaKey, mediaType);
    
    const encFilePath = join(getTmpFilesDirectory(), mediaType + generateMessageIDV2() + '-enc');
    const encFileWriteStream = createWriteStream(encFilePath);
    
    let originalFileStream;
    let originalFilePath;
    
    if (saveOriginalFileIfRequired) {
        originalFilePath = join(getTmpFilesDirectory(), mediaType + generateMessageIDV2() + '-original');
        originalFileStream = createWriteStream(originalFilePath);
    }
    
    let fileLength = 0;
    const aes = Crypto.createCipheriv('aes-256-cbc', cipherKey, iv);
    const hmac = Crypto.createHmac('sha256', macKey).update(iv);
    const sha256Plain = Crypto.createHash('sha256');
    const sha256Enc = Crypto.createHash('sha256');
    
    const onChunk = (buff) => {
        sha256Enc.update(buff);
        hmac.update(buff);
        if (!encFileWriteStream.write(buff)) {
            // Wait for drain if buffer is full
            return new Promise(resolve => encFileWriteStream.once('drain', resolve));
        }
        return Promise.resolve();
    };
    
    try {
        for await (const data of stream) {
            fileLength += data.length;
            
            // Check content length for remote streams
            if (type === 'remote' && opts?.maxContentLength && fileLength > opts.maxContentLength) {
                throw new Boom(`content length exceeded when encrypting "${type}"`, {
                    data: { media, type }
                });
            }
            
            // Write to original file if required
            if (originalFileStream) {
                if (!originalFileStream.write(data)) {
                    await once(originalFileStream, 'drain');
                }
            }
            
            // Update hashes
            sha256Plain.update(data);
            
            // Encrypt and write
            await onChunk(aes.update(data));
        }
        
        // Finalize encryption
        const finalChunk = aes.final();
        await onChunk(finalChunk);
        
        // Calculate and write MAC
        const mac = hmac.digest().slice(0, 10);
        sha256Enc.update(mac);
        await onChunk(mac);
        
        // Finalize streams
        encFileWriteStream.end();
        if (originalFileStream) {
            originalFileStream.end();
        }
        
        // Get final hashes
        const fileSha256 = sha256Plain.digest();
        const fileEncSha256 = sha256Enc.digest();
        
        // Clean up streams
        stream.destroy();
        
        logger?.debug('encrypted data successfully');
        
        return {
            mediaKey,
            originalFilePath,
            encFilePath,
            mac,
            fileEncSha256,
            fileSha256,
            fileLength
        };
    } catch (error) {
        // Clean up all streams and files
        encFileWriteStream.destroy();
        if (originalFileStream) {
            originalFileStream.destroy();
        }
        aes.destroy();
        stream.destroy();
        
        // Delete temporary files
        const cleanupPromises = [fs.unlink(encFilePath).catch(() => {})];
        if (originalFilePath) {
            cleanupPromises.push(fs.unlink(originalFilePath).catch(() => {}));
        }
        
        await Promise.all(cleanupPromises);
        
        logger?.error({ err: error }, 'failed encrypting stream');
        throw error;
    }
};

const DEF_HOST = 'mmg.whatsapp.net';
const AES_CHUNK_SIZE = 16;

const toSmallestChunkSize = (num) => {
    return Math.floor(num / AES_CHUNK_SIZE) * AES_CHUNK_SIZE;
};

export const getUrlFromDirectPath = (directPath) => `https://${DEF_HOST}${directPath}`;

export const downloadContentFromMessage = async ({ mediaKey, directPath, url }, type, opts = {}) => {
    const isValidMediaUrl = url?.startsWith('https://mmg.whatsapp.net/');
    const downloadUrl = isValidMediaUrl ? url : getUrlFromDirectPath(directPath);
    
    if (!downloadUrl) {
        throw new Boom('No valid media URL or directPath present in message', { statusCode: 400 });
    }
    
    const keys = await getMediaKeys(mediaKey, type);
    return downloadEncryptedContent(downloadUrl, keys, opts);
};

/**
 * Decrypts and downloads an AES256-CBC encrypted file given the keys.
 */
export const downloadEncryptedContent = async (downloadUrl, { cipherKey, iv }, { startByte, endByte, options } = {}) => {
    let bytesFetched = 0;
    let startChunk = 0;
    let firstBlockIsIV = false;
    
    // if a start byte is specified -- then we need to fetch the previous chunk as that will form the IV
    if (startByte) {
        const chunk = toSmallestChunkSize(startByte || 0);
        if (chunk) {
            startChunk = chunk - AES_CHUNK_SIZE;
            bytesFetched = chunk;
            firstBlockIsIV = true;
        }
    }
    
    const endChunk = endByte ? toSmallestChunkSize(endByte || 0) + AES_CHUNK_SIZE : undefined;
    
    const headers = {
        ...(options?.headers || {}),
        Origin: DEFAULT_ORIGIN
    };
    
    if (startChunk || endChunk) {
        headers.Range = `bytes=${startChunk}-`;
        if (endChunk) {
            headers.Range += endChunk;
        }
    }
    
    // download the message with timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 300000); // 5 minute timeout
    
    try {
        const fetched = await getHttpStream(downloadUrl, {
            ...options,
            headers,
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        let remainingBytes = Buffer.from([]);
        let aes;
        
        const pushBytes = (bytes, push) => {
            if (startByte || endByte) {
                const start = bytesFetched >= startByte ? undefined : Math.max(startByte - bytesFetched, 0);
                const end = bytesFetched + bytes.length < endByte ? undefined : Math.max(endByte - bytesFetched, 0);
                const sliced = bytes.slice(start, end);
                if (sliced.length > 0) {
                    push(sliced);
                }
                bytesFetched += bytes.length;
            } else {
                push(bytes);
            }
        };
        
        const output = new Transform({
            highWaterMark: 64 * 1024, // 64KB buffer size
            transform(chunk, _, callback) {
                let data = Buffer.concat([remainingBytes, chunk]);
                const decryptLength = toSmallestChunkSize(data.length);
                remainingBytes = data.slice(decryptLength);
                data = data.slice(0, decryptLength);
                
                if (!aes) {
                    let ivValue = iv;
                    if (firstBlockIsIV) {
                        ivValue = data.slice(0, AES_CHUNK_SIZE);
                        data = data.slice(AES_CHUNK_SIZE);
                    }
                    
                    aes = Crypto.createDecipheriv('aes-256-cbc', cipherKey, ivValue);
                    if (endByte) {
                        aes.setAutoPadding(false);
                    }
                }
                
                try {
                    if (data.length > 0) {
                        pushBytes(aes.update(data), b => this.push(b));
                    }
                    callback();
                } catch (error) {
                    callback(error);
                }
            },
            final(callback) {
                try {
                    pushBytes(aes.final(), b => this.push(b));
                    callback();
                } catch (error) {
                    callback(error);
                }
            }
        });
        
        return fetched.pipe(output, { end: true });
    } catch (error) {
        clearTimeout(timeoutId);
        throw error;
    }
};

export function extensionForMediaMessage(message) {
    const getExtension = (mimetype) => mimetype.split(';')[0]?.split('/')[1];
    const type = Object.keys(message)[0];
    let extension;
    
    if (type === 'locationMessage' || type === 'liveLocationMessage' || type === 'productMessage') {
        extension = '.jpeg';
    } else {
        const messageContent = message[type];
        extension = getExtension(messageContent.mimetype);
    }
    
    return extension;
}

export const getWAUploadToServer = ({ customUploadHosts, fetchAgent, logger, options }, refreshMediaConn) => {
    return async (filePath, { mediaType, fileEncSha256B64, timeoutMs }) => {
        // send a query JSON to obtain the url & auth token to upload our media
        let uploadInfo = await refreshMediaConn(false);
        let urls;
        const hosts = [...customUploadHosts, ...uploadInfo.hosts];
        
        fileEncSha256B64 = encodeBase64EncodedStringForUpload(fileEncSha256B64);
        
        for (const { hostname } of hosts) {
            logger.debug(`uploading to "${hostname}"`);
            const auth = encodeURIComponent(uploadInfo.auth);
            const url = `https://${hostname}${MEDIA_PATH_MAP[mediaType]}/${fileEncSha256B64}?auth=${auth}&token=${fileEncSha256B64}`;
            
            let result;
            try {
                const controller = new AbortController();
                const timeoutId = timeoutMs ? setTimeout(() => controller.abort(), timeoutMs) : null;
                
                const stream = createReadStream(filePath);
                const response = await fetch(url, {
                    dispatcher: fetchAgent,
                    method: 'POST',
                    body: stream,
                    headers: {
                        'Content-Type': 'application/octet-stream',
                        Origin: DEFAULT_ORIGIN,
                        ...(options?.headers || {})
                    },
                    signal: controller.signal
                });
                
                if (timeoutId) clearTimeout(timeoutId);
                
                result = await response.json().catch(() => ({}));
                
                if (result?.url || result?.directPath) {
                    urls = {
                        mediaUrl: result.url,
                        directPath: result.direct_path,
                        meta_hmac: result.meta_hmac,
                        fbid: result.fbid,
                        ts: result.ts
                    };
                    break;
                } else {
                    uploadInfo = await refreshMediaConn(true);
                    throw new Error(`upload failed, reason: ${JSON.stringify(result)}`);
                }
            } catch (error) {
                const isLast = hostname === hosts[hosts.length - 1]?.hostname;
                logger.warn({ trace: error?.stack, uploadResult: result }, 
                    `Error in uploading to ${hostname} ${isLast ? '' : ', retrying...'}`);
                
                if (isLast) {
                    throw new Boom('Media upload failed on all hosts', { statusCode: 500 });
                }
            }
        }
        
        if (!urls) {
            throw new Boom('Media upload failed on all hosts', { statusCode: 500 });
        }
        
        return urls;
    };
};

const getMediaRetryKey = (mediaKey) => {
    return hkdf(mediaKey, 32, { info: 'WhatsApp Media Retry Notification' });
};

/**
 * Generate a binary node that will request the phone to re-upload the media & return the newly uploaded URL
 */
export const encryptMediaRetryRequest = async (key, mediaKey, meId) => {
    const recp = { stanzaId: key.id };
    const recpBuffer = proto.ServerErrorReceipt.encode(recp).finish();
    const iv = Crypto.randomBytes(12);
    const retryKey = await getMediaRetryKey(mediaKey);
    const ciphertext = aesEncryptGCM(recpBuffer, retryKey, iv, Buffer.from(key.id));
    
    const req = {
        tag: 'receipt',
        attrs: {
            id: key.id,
            to: jidNormalizedUser(meId),
            type: 'server-error'
        },
        content: [
            {
                tag: 'encrypt',
                attrs: {},
                content: [
                    { tag: 'enc_p', attrs: {}, content: ciphertext },
                    { tag: 'enc_iv', attrs: {}, content: iv }
                ]
            },
            {
                tag: 'rmr',
                attrs: {
                    jid: key.remoteJid,
                    from_me: (!!key.fromMe).toString(),
                    participant: key.participant || undefined
                }
            }
        ]
    };
    
    return req;
};

export const decodeMediaRetryNode = (node) => {
    const rmrNode = getBinaryNodeChild(node, 'rmr');
    const event = {
        key: {
            id: node.attrs.id,
            remoteJid: rmrNode.attrs.jid,
            fromMe: rmrNode.attrs.from_me === 'true',
            participant: rmrNode.attrs.participant
        }
    };
    
    const errorNode = getBinaryNodeChild(node, 'error');
    if (errorNode) {
        const errorCode = +errorNode.attrs.code;
        event.error = new Boom(`Failed to re-upload media (${errorCode})`, {
            data: errorNode.attrs,
            statusCode: getStatusCodeForMediaRetry(errorCode)
        });
    } else {
        const encryptedInfoNode = getBinaryNodeChild(node, 'encrypt');
        const ciphertext = getBinaryNodeChildBuffer(encryptedInfoNode, 'enc_p');
        const iv = getBinaryNodeChildBuffer(encryptedInfoNode, 'enc_iv');
        if (ciphertext && iv) {
            event.media = { ciphertext, iv };
        } else {
            event.error = new Boom('Failed to re-upload media (missing ciphertext)', { statusCode: 404 });
        }
    }
    
    return event;
};

export const decryptMediaRetryData = async ({ ciphertext, iv }, mediaKey, msgId) => {
    const retryKey = await getMediaRetryKey(mediaKey);
    const plaintext = aesDecryptGCM(ciphertext, retryKey, iv, Buffer.from(msgId));
    return proto.MediaRetryNotification.decode(plaintext);
};

export const getStatusCodeForMediaRetry = (code) => MEDIA_RETRY_STATUS_MAP[code];

const MEDIA_RETRY_STATUS_MAP = {
    [proto.MediaRetryNotification.ResultType.SUCCESS]: 200,
    [proto.MediaRetryNotification.ResultType.DECRYPTION_ERROR]: 412,
    [proto.MediaRetryNotification.ResultType.NOT_FOUND]: 404,
    [proto.MediaRetryNotification.ResultType.GENERAL_ERROR]: 418
};
