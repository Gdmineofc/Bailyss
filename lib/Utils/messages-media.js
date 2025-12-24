import { Boom } from '@hapi/boom';
import { exec } from 'child_process';
import * as Crypto from 'crypto';
import { once } from 'events';
import { createReadStream, createWriteStream, promises as fs } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { Readable, Transform } from 'stream';
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
        const cmd = `ffmpeg -ss ${time} -i "${path}" -y -vf scale=${size.width}:-1 -vframes 1 -f image2 "${destPath}"`;
        exec(cmd, (err) => {
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

export const mediaMessageSHA256B64 = (message) => {
    const media = Object.values(message)[0];
    return media?.fileSha256 && Buffer.from(media.fileSha256).toString('base64');
};

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

export const getHttpStream = async (url, options = {}) => {
    const controller = new AbortController();
    const timeout = options.timeout || 30000;
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    try {
        const response = await fetch(url.toString(), {
            signal: controller.signal,
            dispatcher: options.dispatcher,
            method: 'GET',
            headers: options.headers
        });
        
        clearTimeout(timeoutId);
        
        if (!response.ok) {
            throw new Boom(`Failed to fetch stream from ${url}`, { 
                statusCode: response.status, 
                data: { url } 
            });
        }
        
        return Readable.fromWeb(response.body);
    } catch (error) {
        clearTimeout(timeoutId);
        throw error;
    }
};

// FIXED: This is the main memory leak fix for large file downloads
export const downloadEncryptedContent = async (downloadUrl, { cipherKey, iv }, { startByte, endByte, options } = {}) => {
    let bytesFetched = 0;
    let startChunk = 0;
    let firstBlockIsIV = false;
    
    if (startByte) {
        const chunk = Math.floor(startByte / 16) * 16;
        if (chunk) {
            startChunk = chunk - 16;
            bytesFetched = chunk;
            firstBlockIsIV = true;
        }
    }
    
    const endChunk = endByte ? Math.floor(endByte / 16) * 16 + 16 : undefined;
    
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
    
    let fetched;
    try {
        fetched = await getHttpStream(downloadUrl, {
            ...(options || {}),
            headers,
            timeout: 300000 // 5 minute timeout for large files
        });
    } catch (error) {
        throw new Boom(`Failed to download from ${downloadUrl}: ${error.message}`, {
            statusCode: error.statusCode || 500
        });
    }
    
    let remainingBytes = Buffer.alloc(0);
    let aes = null;
    let isDestroyed = false;
    
    // Create a proper transform stream with backpressure handling
    const output = new Transform({
        highWaterMark: 64 * 1024, // 64KB buffer size
        transform(chunk, encoding, callback) {
            if (isDestroyed) {
                return callback();
            }
            
            try {
                // Concatenate with any remaining bytes
                let data = Buffer.concat([remainingBytes, chunk]);
                const blockSize = 16;
                const completeBlocks = Math.floor(data.length / blockSize) * blockSize;
                
                // Keep incomplete block for next chunk
                remainingBytes = data.slice(completeBlocks);
                data = data.slice(0, completeBlocks);
                
                if (data.length === 0) {
                    return callback();
                }
                
                // Initialize AES decipher if not done yet
                if (!aes) {
                    let ivValue = iv;
                    if (firstBlockIsIV) {
                        if (data.length < 16) {
                            // Not enough data for IV, wait for more
                            remainingBytes = Buffer.concat([remainingBytes, data]);
                            return callback();
                        }
                        ivValue = data.slice(0, 16);
                        data = data.slice(16);
                    }
                    
                    try {
                        aes = Crypto.createDecipheriv('aes-256-cbc', cipherKey, ivValue);
                        if (endByte) {
                            aes.setAutoPadding(false);
                        }
                    } catch (err) {
                        return callback(err);
                    }
                }
                
                // Decrypt and push data
                if (data.length > 0) {
                    let decrypted;
                    try {
                        decrypted = aes.update(data);
                    } catch (err) {
                        return callback(err);
                    }
                    
                    if (decrypted && decrypted.length > 0) {
                        // Apply byte range filtering if needed
                        if (startByte || endByte) {
                            const start = bytesFetched >= startByte ? undefined : Math.max(startByte - bytesFetched, 0);
                            const end = bytesFetched + decrypted.length < endByte ? undefined : Math.max(endByte - bytesFetched, 0);
                            const sliced = decrypted.slice(start, end);
                            
                            if (sliced.length > 0) {
                                bytesFetched += decrypted.length;
                                
                                // Handle backpressure
                                if (!this.push(sliced)) {
                                    // Pause upstream if we can't push more
                                    fetched.pause();
                                    this.once('drain', () => {
                                        fetched.resume();
                                    });
                                }
                            }
                        } else {
                            // Handle backpressure
                            if (!this.push(decrypted)) {
                                fetched.pause();
                                this.once('drain', () => {
                                    fetched.resume();
                                });
                            }
                        }
                    }
                }
                
                callback();
            } catch (error) {
                callback(error);
            }
        },
        
        flush(callback) {
            if (isDestroyed) {
                return callback();
            }
            
            try {
                if (aes) {
                    let finalData;
                    try {
                        finalData = aes.final();
                    } catch (err) {
                        // Ignore padding errors when range is specified
                        if (!endByte) {
                            return callback(err);
                        }
                        finalData = Buffer.alloc(0);
                    }
                    
                    if (finalData && finalData.length > 0) {
                        // Apply byte range filtering for final data
                        if (startByte || endByte) {
                            const start = bytesFetched >= startByte ? undefined : Math.max(startByte - bytesFetched, 0);
                            const end = bytesFetched + finalData.length < endByte ? undefined : Math.max(endByte - bytesFetched, 0);
                            const sliced = finalData.slice(start, end);
                            
                            if (sliced.length > 0) {
                                this.push(sliced);
                            }
                        } else {
                            this.push(finalData);
                        }
                    }
                }
                
                // Clean up
                remainingBytes = Buffer.alloc(0);
                callback();
            } catch (error) {
                callback(error);
            }
        },
        
        final(callback) {
            this.flush(callback);
        },
        
        destroy(error, callback) {
            isDestroyed = true;
            
            // Clean up all resources
            if (aes) {
                try {
                    aes.destroy();
                } catch (e) {
                    // Ignore
                }
                aes = null;
            }
            
            remainingBytes = Buffer.alloc(0);
            
            if (fetched && !fetched.destroyed) {
                fetched.destroy(error);
            }
            
            callback(error);
        }
    });
    
    // Handle errors
    fetched.on('error', (error) => {
        if (!isDestroyed) {
            output.destroy(error);
        }
    });
    
    output.on('error', (error) => {
        if (!isDestroyed) {
            fetched.destroy(error);
        }
    });
    
    // Handle premature close
    output.on('close', () => {
        isDestroyed = true;
        if (aes) {
            try {
                aes.destroy();
            } catch (e) {
                // Ignore
            }
            aes = null;
        }
        remainingBytes = Buffer.alloc(0);
    });
    
    // Pipe with end flag
    fetched.pipe(output, { end: true });
    
    return output;
};

export const downloadContentFromMessage = async ({ mediaKey, directPath, url }, type, opts = {}) => {
    const isValidMediaUrl = url?.startsWith('https://mmg.whatsapp.net/');
    const downloadUrl = isValidMediaUrl ? url : `https://mmg.whatsapp.net${directPath}`;
    
    if (!downloadUrl) {
        throw new Boom('No valid media URL or directPath present in message', { statusCode: 400 });
    }
    
    const keys = await getMediaKeys(mediaKey, type);
    return downloadEncryptedContent(downloadUrl, keys, opts);
};

// Simple helper function to get extension
export function extensionForMediaMessage(message) {
    const getExtension = (mimetype) => mimetype?.split(';')[0]?.split('/')[1];
    const type = Object.keys(message)[0];
    
    if (type === 'locationMessage' || type === 'liveLocationMessage' || type === 'productMessage') {
        return '.jpeg';
    }
    
    const messageContent = message[type];
    return getExtension(messageContent?.mimetype);
}

export const getWAUploadToServer = ({ customUploadHosts, fetchAgent, logger, options }, refreshMediaConn) => {
    return async (filePath, { mediaType, fileEncSha256B64, timeoutMs }) => {
        let uploadInfo = await refreshMediaConn(false);
        let urls;
        const hosts = [...customUploadHosts, ...uploadInfo.hosts];
        
        fileEncSha256B64 = encodeBase64EncodedStringForUpload(fileEncSha256B64);
        
        for (const { hostname } of hosts) {
            logger?.debug(`uploading to "${hostname}"`);
            const auth = encodeURIComponent(uploadInfo.auth);
            const url = `https://${hostname}${MEDIA_PATH_MAP[mediaType]}/${fileEncSha256B64}?auth=${auth}&token=${fileEncSha256B64}`;
            
            let result;
            let stream;
            try {
                stream = createReadStream(filePath);
                const controller = new AbortController();
                const timeoutId = timeoutMs ? setTimeout(() => controller.abort(), timeoutMs) : null;
                
                const response = await fetch(url, {
                    dispatcher: fetchAgent,
                    method: 'POST',
                    body: stream,
                    headers: {
                        'Content-Type': 'application/octet-stream',
                        Origin: DEFAULT_ORIGIN,
                        ...options?.headers
                    },
                    signal: controller.signal
                });
                
                if (timeoutId) clearTimeout(timeoutId);
                
                try {
                    result = await response.json();
                } catch {
                    result = undefined;
                }
                
                if (response.ok && (result?.url || result?.directPath)) {
                    urls = {
                        mediaUrl: result.url,
                        directPath: result.direct_path,
                        meta_hmac: result.meta_hmac,
                        fbid: result.fbid,
                        ts: result.ts
                    };
                    stream.destroy();
                    break;
                } else {
                    stream.destroy();
                    uploadInfo = await refreshMediaConn(true);
                    throw new Error(`upload failed: ${JSON.stringify(result)}`);
                }
            } catch (error) {
                if (stream && !stream.destroyed) {
                    stream.destroy();
                }
                
                const isLast = hostname === hosts[hosts.length - 1]?.hostname;
                logger?.warn(`Error uploading to ${hostname}${isLast ? '' : ', retrying...'}: ${error.message}`);
                
                if (isLast) break;
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

export const encryptMediaRetryRequest = async (key, mediaKey, meId) => {
    const recp = { stanzaId: key.id };
    const recpBuffer = proto.ServerErrorReceipt.encode(recp).finish();
    
    const iv = Crypto.randomBytes(12);
    const retryKey = await getMediaRetryKey(mediaKey);
    const ciphertext = aesEncryptGCM(recpBuffer, retryKey, iv, Buffer.from(key.id));
    
    return {
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

export const getStatusCodeForMediaRetry = (code) => {
    const MEDIA_RETRY_STATUS_MAP = {
        [proto.MediaRetryNotification.ResultType.SUCCESS]: 200,
        [proto.MediaRetryNotification.ResultType.DECRYPTION_ERROR]: 412,
        [proto.MediaRetryNotification.ResultType.NOT_FOUND]: 404,
        [proto.MediaRetryNotification.ResultType.GENERAL_ERROR]: 418
    };
    return MEDIA_RETRY_STATUS_MAP[code];
};
