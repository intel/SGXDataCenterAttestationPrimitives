/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path  = require('path');

const Buffer = require('../util/buffer');
const logger = require('./logger').genericLogger;

function getRealPathFromFileDescriptor(fd) {
    return fs.readlinkSync('/proc/self/fd/' + fd);
}

/**
 * Reads file using file descriptor, blocking changes in the meantime
 * In case filePath is a symlink, it checks where it directs and if target path is in allowed location
 * inside user home directory or allowed mount point
 *
 * @param {string} filePath - path to file to read
 * @param {string} encoding - default is 'utf8'
 * @returns {string} file content
 */
function readFileSafely(filePath, encoding = 'utf8') {
    const absolutePath = path.resolve(filePath);
    const allowedLocations = [
        os.homedir() + path.sep,    // user home directory
    ];
    const fd = fs.openSync(absolutePath);
    let content = '';
    try {
        const link = getRealPathFromFileDescriptor(fd);
        logger.trace('Loading file from: ' + absolutePath);
        if (absolutePath !== link) {
            logger.debug('Loading file from symlink: ' + absolutePath + ' which directs to: ' + link);
            const locationAllowed = allowedLocations.some((prefix) => link.startsWith(prefix));
            if (!locationAllowed) {
                throw new Error('Loading link which directs outside of provided locations: ' + JSON.stringify(allowedLocations) + ' is forbidden!');
            }
        }

        const stat = fs.fstatSync(fd);
        if (stat.isDirectory()) {
            throw new Error(`Expected path to a file, not a directory. Are you sure path "${filePath}" is correct?`);
        }
        const buff = Buffer.alloc(stat.size);
        fs.readSync(fd, buff, 0, buff.length);
        content = buff.toString(encoding);
    }
    catch (err) {
        logger.error('Problem loading file: ' + err);
        throw err;
    }
    finally {
        try {
            fs.closeSync(fd);
        }
        catch (err) {
            logger.error('Problem closing file ' + fd + ': ' + err);
        }
    }
    return content;
}

module.exports = readFileSafely;
