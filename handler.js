'use strict';
const AWS = require('aws-sdk');
const s3 = new AWS.S3();
const fs = require('fs');
const uuidv4 = require('uuid/v4')
const VirusTotalApi = require('virustotal-api');
const virusTotal = new VirusTotalApi('<YOUR_API_KEY>');

module.exports.s3hook = async (event) => {
    const bucket = event.Records[0].s3.bucket.name;
    const filename = decodeURIComponent(event.Records[0].s3.object.key.replace(/\+/g, ' '));
    const params = {
        Bucket: bucket,
        Key: filename
    }

    const fileNameDownloaded = `/tmp/${uuidv4()}_${filename}`;

    await s3.getObject(params).promise()
        .then(f => downloadFile(fileNameDownloaded, f))
        .then(f => scanFile(f))
        .then(f => {
            console.log(`${f} is ok`);
        })
        .catch(async err => {
            console.error(err);
            await s3.deleteObject(params).promise().then(f => {
                console.log(`${filename} is deleted`);
            }).catch(err => {
                console.error(err);
            })
        });
};

async function downloadFile(fileName, data) {
    return new Promise(((resolve) => {
        fs.writeFileSync(fileName, data.Body.toString());
        console.info(`file ${fileName} downloaded`);
        resolve(fileName);
    }))
}

async function getFileReport(resource) {
    return new Promise((async (resolve) => {
        let responseCode = 0;
        let result = null;
        do {
            result = await virusTotal.fileReport(resource);
            responseCode = result.response_code;
            if (responseCode == 1) {
                break;
            }
            await new Promise(r => setTimeout(r,  60 * 1000));
        } while (responseCode != 1);
        resolve(result);
    }));
}

async function scanFile(filePath) {
    return new Promise((resolve, reject) => {
        fs.readFile(filePath, (err, data) => {
            if (err) {
                console.log(err);
                reject(err);
            } else {
                let filename = filePath.replace(/^.*[\\\/]/, '');
                console.log(`Scanning ${filename} ..............`);
                virusTotal.fileScan(data, filename)
                    .then(response => {
                        return getFileReport(response.resource);
                    })
                    .then(response => {
                        for (let [k, v] of Object.entries(response.scans)) {
                            if (v.detected) {
                                reject(new Error(`${filename} is infected`));
                            }
                        }
                        resolve(filename);
                    }).catch(err => {
                    console.log(`ERROR = ${err}`);
                    reject(err);
                })
            }
        });
    });
}
