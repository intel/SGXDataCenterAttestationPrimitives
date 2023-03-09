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

const assert = require('assert');
const util = require('util');
const _ = require('lodash');

function assertMockFirstCalledWithArgs(mock, ...args) {
    assertMockCalledWithArgs(0, mock, ...args);
}

function assertMockCalledWithArgs(call, mock, ...args) {
    assert(call < mock.callCount, 'Mock not called enough times');
    assert.strictEqual(mock.args[call].length, args.length);
    for (const [index, value] of args.entries()) {
        if (util.isObject(value)) {
            assert.deepStrictEqual(mock.args[call][index], value);
        }
        else {
            assert.strictEqual(mock.args[call][index], value);
        }
    }
}

function getCallCountWithArgs(mock, ...args) {
    let callCount = 0;
    for (let callIndex = 0; callIndex < mock.callCount; callIndex++) {
        let argsFound = true;
        for (const [index, value] of args.entries()) {
            argsFound = argsFound && _.isEqual(mock.args[callIndex][index], value);
            if (!argsFound) {
                break;
            }
        }
        if (argsFound) {
            callCount++;
        }
    }

    return callCount;
}

function assertMockCalledNTimesWithArgs(expectedAllCount, mock, ...args) {
    const times = getCallCountWithArgs(mock, ...args);
    assert(expectedAllCount === times,
        `Mock called with args (${args}) ${times} out of ${expectedAllCount} times.`);
}

function assertMockCalledOnceWithArgs(mock, ...args) {
    assertMockCalledNTimesWithArgs(1, mock, ...args);
}

// regular assert.throws would not work with async, hence this helper
async function assertThrowsAsync(testPromise, expectedError) {
    try {
        await testPromise();
    }
    catch (err) {
        if (err instanceof expectedError) {
            return;
        }
        else {
            assert.fail(util.format(
                'Assertion failed: exception of invalid type was thrown: [%s], required type: [%s]',
                err.name,
                expectedError.name));
        }

    }
    assert.fail(util.format('Assertion failed: no exception was thrown'));
}

module.exports = {
    assertMockCalledWithArgs,
    assertMockFirstCalledWithArgs,
    assertMockCalledNTimesWithArgs,
    assertMockCalledOnceWithArgs,
    assertThrowsAsync
};
