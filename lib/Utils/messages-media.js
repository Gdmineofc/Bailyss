import { Boom } from '@hapi/boom';
import { exec } from 'child_process';
import * as Crypto from 'crypto';
import { once } from 'events';
import { createReadStream, createWriteStream, promises as fs } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { Readable, Transform, PassThrough } from 'stream';
import { pipeline } from 'stream/promises';
import { proto } from '../../WAProto/index.js';
import { DEFAULT_ORIGIN, MEDIA_HKDF_KEY_MAPPING, MEDIA_PATH_MAP } from '../Defaults/index.js';
import { getBinaryNodeChild, getBinaryNodeChildBuffer, jidNormalizedUser } from '../WABinary/index.js';
import { aesDecryptGCM, aesEncryptGCM, hkdf } from './crypto.js';
import { generateMessageIDV2 } from './generics.js';

const getTmpFilesDirectory = () => tmpdir();

const getImageProcessingLibrary = async () => {
    const [jimp, sharp] = await Promise.all([
        import('jimp').catch(() => {}),
        import('sharp').catch(() => {})
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

export const getRawMediaUploadData = async (media, mediaType, logger) => {
    const { stream } = await getStream(media);
    logger?.debug('got stream for raw upload');
    
    const hasher = Crypto.createHash('sha256');
    const filePath = join(tmpdir(), mediaType + generateMessageIDV2());
    const fileWriteStream = createWriteStream(filePath);
    
    let fileLength = 0;
    try {
        await pipeline(
            stream,
            new Transform({
                transform(chunk, encoding, callback) {
                    fileLength += chunk.length;
                    hasher.update(chunk);
                    this.push(chunk);
                    callback();
                }
            }),
            fileWriteStream
        );
        
        const fileSha256 = hasher.digest();
        logger?.debug('hashed data for raw upload');
        
        return {
            filePath,
            fileSha256,
            fileLength
        };
    } catch (error) {
        fileWriteStream.destroy();
        stream.destroy();
        try {
            await fs.unlink(filePath);
        } catch {
            // ignore
        }
        throw error;
    }
};

export async function getMediaKeys(buffer, mediaType) {
    if (!buffer) {
        throw new Boom('Cannot derive from empty media key');
    }
    
    if (typeof buffer === 'string') {
        buffer = Buffer.from(buffer.replace('data:;base64,', ''), 'base64');
    }
    
    const expandedMediaKey = await hkdf(buffer, 112, { info: hkdfInfoKey(mediaType) });
    return {
        iv: expandedMediaKey.slice(0, 16),
        cipherKey: expandedMediaKey.slice(16, 48),
        macKey: expandedMediaKey.slice(48, 80)
    };
}

const extractVideoThumb = async (path, destPath, time, size) => 
    new Promise((resolve, reject) => {
        const cmd = `ffmpeg -ss ${time} -i ${path} -y -vf scale=${size.width}:-1 -vframes 1 -f image2 ${destPath}`;
        exec(cmd, err => {
            if (err) {
                reject(err);
            } else {
                resolve();
            }
        });
    });

export const extractImageThumb = async (bufferOrFilePath, width = 32) => {
    if (bufferOrFilePath instanceof Readable) {
        bufferOrFilePath = await toBuffer(bufferOrFilePath);
    }
    
    const lib = await getImageProcessingLibrary();
    
    if ('sharp' in lib && lib.sharp?.default) {
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
    } else if ('jimp' in lib && lib.jimp?.Jimp) {
        const jimp = await lib.jimp.Jimp.read(bufferOrFilePath);
        const dimensions = {
            width: jimp.width,
            height: jimp.height
        };
        const buffer = await jimp
            .resize({ w: width, mode: lib.jimp.ResizeStrategy.BILINEAR })
            .getBuffer('image/jpeg', { quality: 50 });
        return {
            buffer,
            original: dimensions
        };
    } else {
        throw new Boom('No image processing library available');
    }
};

export const encodeBase64EncodedStringForUpload = (b64) => 
    encodeURIComponent(b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=+$/, ''));

export const generateProfilePicture = async (mediaUpload, dimensions) => {
    let buffer;
    const { width: w = 640, height: h = 640 } = dimensions || {};
    
    if (Buffer.isBuffer(mediaUpload)) {
        buffer = mediaUpload;
    } else {
        const { stream } = await getStream(mediaUpload);
        buffer = await toBuffer(stream);
    }
    
    const lib = await getImageProcessingLibrary();
    let img;
    
    if ('sharp' in lib && lib.sharp?.default) {
        img = lib.sharp
            .default(buffer)
            .resize(w, h)
            .jpeg({ quality: 50 })
            .toBuffer();
    } else if ('jimp' in lib && lib.jimp?.Jimp) {
        const jimp = await lib.jimp.Jimp.read(buffer);
        const min = Math.min(jimp.width, jimp.height);
        const cropped = jimp.crop({ x: 0, y: 0, w: min, h: min });
        img = cropped.resize({ w, h, mode: lib.jimp.ResizeStrategy.BILINEAR }).getBuffer('image/jpeg', { quality: 50 });
    } else {
        throw new Boom('No image processing library available');
    }
    
    return {
        img: await img
    };
};

export const mediaMessageSHA256B64 = (message) => {
    const media = Object.values(message)[0];
    return media?.fileSha256 && Buffer.from(media.fileSha256).toString('base64');
};

export async function getAudioDuration(buffer) {
    const musicMetadata = await import('music-metadata');
    let metadata;
    const options = { duration: true };
    
    if (Buffer.isBuffer(buffer)) {
        metadata = await musicMetadata.parseBuffer(buffer, undefined, options);
    } else if (typeof buffer === 'string') {
        metadata = await musicMetadata.parseFile(buffer, options);
    } else {
        // For streams, read only the beginning to get duration
        const stream = buffer;
        const chunkSize = 4096;
        const chunks: Buffer[] = [];
        let totalBytes = 0;
        
        for await (const chunk of stream) {
            chunks.push(chunk);
            totalBytes += chunk.length;
            if (totalBytes >= chunkSize * 10) { // Read only ~40KB to get metadata
                break;
            }
        }
        
        // Restore stream if needed
        if (!stream.destroyed) {
            const passThrough = new PassThrough();
            // Push the chunks we read back
            for (const chunk of chunks) {
                passThrough.write(chunk);
            }
            // Pipe the remaining data
            stream.pipe(passThrough);
        }
        
        const bufferData = Buffer.concat(chunks);
        metadata = await musicMetadata.parseBuffer(bufferData, undefined, options);
    }
    
    return metadata.format.duration;
}

export async function getAudioWaveform(buffer, logger) {
    try {
        const { default: decoder } = await import('audio-decode');
        let audioData;
        
        if (Buffer.isBuffer(buffer)) {
            audioData = buffer;
        } else if (typeof buffer === 'string') {
            const rStream = createReadStream(buffer);
            audioData = await toBuffer(rStream);
        } else {
            // For streams, only read what's needed
            const MAX_AUDIO_SIZE = 10 * 1024 * 1024; // 10MB max for waveform
            const chunks: Buffer[] = [];
            let totalSize = 0;
            
            for await (const chunk of buffer) {
                chunks.push(chunk);
                totalSize += chunk.length;
                if (totalSize >= MAX_AUDIO_SIZE) {
                    break;
                }
            }
            audioData = Buffer.concat(chunks);
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

export const toBuffer = async (stream) => {
    const chunks = [];
    for await (const chunk of stream) {
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

export async function generateThumbnail(file, mediaType, options) {
    let thumbnail;
    let originalImageDimensions;
    
    if (mediaType === 'image') {
        const { buffer, original } = await extractImageThumb(file);
        thumbnail = buffer.toString('base64');
        if (original.width && original.height) {
            originalImageDimensions = {
                width: original.width,
                height: original.height
            };
        }
    } else if (mediaType === 'video') {
        const imgFilename = join(getTmpFilesDirectory(), generateMessageIDV2() + '.jpg');
        try {
            await extractVideoThumb(file, imgFilename, '00:00:00', { width: 32 });
            const buff = await fs.readFile(imgFilename);
            thumbnail = buff.toString('base64');
            await fs.unlink(imgFilename);
        } catch (err) {
            options?.logger?.debug('could not generate video thumb: ' + err);
        }
    }
    
    return {
        thumbnail,
        originalImageDimensions
    };
}

export const getHttpStream = async (url, options = {}) => {
    const response = await fetch(url.toString(), {
        dispatcher: options.dispatcher,
        method: 'GET',
        headers: options.headers
    });
    
    if (!response.ok) {
        throw new Boom(`Failed to fetch stream from ${url}`, { 
            statusCode: response.status, 
            data: { url } 
        });
    }
    
    if (!response.body) {
        throw new Boom(`No response body from ${url}`, { statusCode: 500 });
    }
    
    return Readable.fromWeb(response.body);
};

export const encryptedStream = async (media, mediaType, { logger, saveOriginalFileIfRequired, opts } = {}) => {
    const { stream, type } = await getStream(media, opts);
    logger?.debug('fetched media stream');
    
    const mediaKey = Crypto.randomBytes(32);
    const { cipherKey, iv, macKey } = await getMediaKeys(mediaKey, mediaType);
    
    const encFilePath = join(getTmpFilesDirectory(), mediaType + generateMessageIDV2() + '-enc');
    const encFileWriteStream = createWriteStream(encFilePath);
    
    let originalFileStream: ReturnType<typeof createWriteStream> | undefined;
    let originalFilePath: string | undefined;
    
    if (saveOriginalFileIfRequired) {
        originalFilePath = join(getTmpFilesDirectory(), mediaType + generateMessageIDV2() + '-original');
        originalFileStream = createWriteStream(originalFilePath);
    }
    
    let fileLength = 0;
    const aes = Crypto.createCipheriv('aes-256-cbc', cipherKey, iv);
    const hmac = Crypto.createHmac('sha256', macKey).update(iv);
    const sha256Plain = Crypto.createHash('sha256');
    const sha256Enc = Crypto.createHash('sha256');
    
    // Store the result from the pipeline
    let result: {
        mediaKey: Buffer;
        originalFilePath: string | undefined;
        encFilePath: string;
        mac: Buffer;
        fileEncSha256: Buffer;
        fileSha256: Buffer;
        fileLength: number;
    };
    
    try {
        // Use a pass-through to collect the result
        const resultPassThrough = new PassThrough();
        
        await pipeline(
            stream,
            new Transform({
                transform(chunk, encoding, callback) {
                    fileLength += chunk.length;
                    
                    if (type === 'remote' && opts?.maxContentLength && fileLength > opts.maxContentLength) {
                        const error = new Boom(`content length exceeded when encrypting "${type}"`, {
                            data: { media, type }
                        });
                        return callback(error);
                    }
                    
                    if (originalFileStream && !originalFileStream.write(chunk)) {
                        originalFileStream.once('drain', () => callback());
                    } else {
                        callback();
                    }
                    
                    sha256Plain.update(chunk);
                    
                    const encryptedChunk = aes.update(chunk);
                    sha256Enc.update(encryptedChunk);
                    hmac.update(encryptedChunk);
                    
                    if (!encFileWriteStream.write(encryptedChunk)) {
                        encFileWriteStream.once('drain', () => {
                            this.push(encryptedChunk);
                        });
                    } else {
                        this.push(encryptedChunk);
                    }
                },
                
                async flush(callback) {
                    try {
                        const finalEncrypted = aes.final();
                        if (finalEncrypted.length > 0) {
                            sha256Enc.update(finalEncrypted);
                            hmac.update(finalEncrypted);
                            if (!encFileWriteStream.write(finalEncrypted)) {
                                await once(encFileWriteStream, 'drain');
                            }
                            this.push(finalEncrypted);
                        }
                        
                        const mac = hmac.digest().slice(0, 10);
                        sha256Enc.update(mac);
                        
                        encFileWriteStream.write(mac);
                        encFileWriteStream.end();
                        
                        if (originalFileStream) {
                            originalFileStream.end();
                            await once(originalFileStream, 'finish');
                        }
                        
                        await once(encFileWriteStream, 'finish');
                        
                        const fileSha256 = sha256Plain.digest();
                        const fileEncSha256 = sha256Enc.digest();
                        
                        logger?.debug('encrypted data successfully');
                        
                        // Create the result object
                        result = {
                            mediaKey,
                            originalFilePath,
                            encFilePath,
                            mac,
                            fileEncSha256,
                            fileSha256,
                            fileLength
                        };
                        
                        callback();
                    } catch (error) {
                        callback(error);
                    }
                }
            }),
            resultPassThrough
        );
        
        // Return the result after pipeline completes
        return result!;
        
    } catch (error) {
        encFileWriteStream.destroy();
        if (originalFileStream) {
            originalFileStream.destroy();
        }
        aes.destroy();
        stream.destroy();
        
        try {
            await fs.unlink(encFilePath);
            if (originalFilePath) {
                await fs.unlink(originalFilePath);
            }
        } catch (err) {
            logger?.error({ err }, 'failed deleting tmp files');
        }
        throw error;
    }
};

const DEF_HOST = 'mmg.whatsapp.net';
const AES_CHUNK_SIZE = 16;
const toSmallestChunkSize = (num: number) => {
    return Math.floor(num / AES_CHUNK_SIZE) * AES_CHUNK_SIZE;
};

export const getUrlFromDirectPath = (directPath: string) => `https://${DEF_HOST}${directPath}`;

export const downloadContentFromMessage = async ({ mediaKey, directPath, url }: { mediaKey: Buffer; directPath?: string; url?: string }, type: string, opts: any = {}) => {
    const isValidMediaUrl = url?.startsWith('https://mmg.whatsapp.net/');
    const downloadUrl = isValidMediaUrl ? url : getUrlFromDirectPath(directPath || '');
    
    if (!downloadUrl) {
        throw new Boom('No valid media URL or directPath present in message', { statusCode: 400 });
    }
    
    const keys = await getMediaKeys(mediaKey, type);
    return downloadEncryptedContent(downloadUrl, keys, opts);
};

export const downloadEncryptedContent = async (downloadUrl: string, { cipherKey, iv }: { cipherKey: Buffer; iv: Buffer }, { startByte, endByte, options }: any = {}) => {
    let bytesFetched = 0;
    let startChunk = 0;
    let firstBlockIsIV = false;
    
    if (startByte) {
        const chunk = toSmallestChunkSize(startByte || 0);
        if (chunk) {
            startChunk = chunk - AES_CHUNK_SIZE;
            bytesFetched = chunk;
            firstBlockIsIV = true;
        }
    }
    
    const endChunk = endByte ? toSmallestChunkSize(endByte || 0) + AES_CHUNK_SIZE : undefined;
    
    const headersInit = options?.headers ? options.headers : undefined;
    const headers: Record<string, string> = {
        ...(headersInit
            ? Array.isArray(headersInit)
                ? Object.fromEntries(headersInit)
                : headersInit
            : {}),
        Origin: DEFAULT_ORIGIN
    };
    
    if (startChunk || endChunk) {
        headers.Range = `bytes=${startChunk}-`;
        if (endChunk) {
            headers.Range += endChunk;
        }
    }
    
    const fetched = await getHttpStream(downloadUrl, {
        ...(options || {}),
        headers
    });
    
    let remainingBytes = Buffer.alloc(0);
    let aes: Crypto.Decipher | undefined;
    
    const output = new Transform({
        transform(chunk, _, callback) {
            try {
                let data = Buffer.concat([remainingBytes, chunk]);
                const decryptLength = toSmallestChunkSize(data.length);
                
                remainingBytes = data.slice(decryptLength);
                data = data.slice(0, decryptLength);
                
                if (data.length === 0) {
                    return callback();
                }
                
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
                
                if (data.length > 0) {
                    const decrypted = aes.update(data);
                    if (decrypted.length > 0) {
                        // Handle byte range slicing
                        if (startByte || endByte) {
                            const start = bytesFetched >= startByte ? undefined : Math.max(startByte - bytesFetched, 0);
                            const end = bytesFetched + decrypted.length < endByte ? undefined : Math.max(endByte - bytesFetched, 0);
                            const sliced = decrypted.slice(start, end);
                            if (sliced.length > 0) {
                                this.push(sliced);
                            }
                            bytesFetched += decrypted.length;
                        } else {
                            this.push(decrypted);
                        }
                    }
                }
                callback();
            } catch (error) {
                callback(error);
            }
        },
        
        flush(callback) {
            try {
                if (aes) {
                    const finalDecrypted = aes.final();
                    if (finalDecrypted.length > 0) {
                        // Handle byte range slicing for final chunk
                        if (startByte || endByte) {
                            const start = bytesFetched >= startByte ? undefined : Math.max(startByte - bytesFetched, 0);
                            const end = bytesFetched + finalDecrypted.length < endByte ? undefined : Math.max(endByte - bytesFetched, 0);
                            const sliced = finalDecrypted.slice(start, end);
                            if (sliced.length > 0) {
                                this.push(sliced);
                            }
                        } else {
                            this.push(finalDecrypted);
                        }
                    }
                }
                
                remainingBytes = Buffer.alloc(0);
                callback();
            } catch (error) {
                callback(error);
            }
        }
    });
    
    fetched.on('error', (err) => {
        output.destroy(err);
    });
    
    output.on('error', (err) => {
        fetched.destroy(err);
    });
    
    return fetched.pipe(output, { end: true });
};

export function extensionForMediaMessage(message: any) {
    const getExtension = (mimetype: string) => mimetype.split(';')[0]?.split('/')[1];
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

export const getWAUploadToServer = ({ customUploadHosts, fetchAgent, logger, options }: any, refreshMediaConn: any) => {
    return async (filePath: string, { mediaType, fileEncSha256B64, timeoutMs }: { mediaType: string; fileEncSha256B64: string; timeoutMs?: number }) => {
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
                const stream = createReadStream(filePath);
                const response = await fetch(url, {
                    dispatcher: fetchAgent,
                    method: 'POST',
                    body: stream,
                    headers: {
                        ...(() => {
                            const hdrs = options?.headers;
                            if (!hdrs) return {};
                            return Array.isArray(hdrs) ? Object.fromEntries(hdrs) : hdrs;
                        })(),
                        'Content-Type': 'application/octet-stream',
                        Origin: DEFAULT_ORIGIN
                    },
                    duplex: 'half',
                    signal: timeoutMs ? AbortSignal.timeout(timeoutMs) : undefined
                });
                
                let parsed;
                try {
                    parsed = await response.json();
                } catch {
                    parsed = undefined;
                }
                
                result = parsed;
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
                const isLast = hostname === hosts[uploadInfo.hosts.length - 1]?.hostname;
                logger.warn({ trace: error?.stack, uploadResult: result }, 
                    `Error in uploading to ${hostname} ${isLast ? '' : ', retrying...'}`);
            }
        }
        
        if (!urls) {
            throw new Boom('Media upload failed on all hosts', { statusCode: 500 });
        }
        
        return urls;
    };
};

const getMediaRetryKey = (mediaKey: Buffer) => {
    return hkdf(mediaKey, 32, { info: 'WhatsApp Media Retry Notification' });
};

export const encryptMediaRetryRequest = async (key: any, mediaKey: Buffer, meId: string) => {
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

export const decodeMediaRetryNode = (node: any) => {
    const rmrNode = getBinaryNodeChild(node, 'rmr');
    const event: any = {
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

export const decryptMediaRetryData = async ({ ciphertext, iv }: { ciphertext: Buffer; iv: Buffer }, mediaKey: Buffer, msgId: string) => {
    const retryKey = await getMediaRetryKey(mediaKey);
    const plaintext = aesDecryptGCM(ciphertext, retryKey, iv, Buffer.from(msgId));
    return proto.MediaRetryNotification.decode(plaintext);
};

export const getStatusCodeForMediaRetry = (code: number) => MEDIA_RETRY_STATUS_MAP[code];

const MEDIA_RETRY_STATUS_MAP: Record<number, number> = {
    [proto.MediaRetryNotification.ResultType.SUCCESS]: 200,
    [proto.MediaRetryNotification.ResultType.DECRYPTION_ERROR]: 412,
    [proto.MediaRetryNotification.ResultType.NOT_FOUND]: 404,
    [proto.MediaRetryNotification.ResultType.GENERAL_ERROR]: 418
};
