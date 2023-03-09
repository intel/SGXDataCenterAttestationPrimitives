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

/**
 * @typedef {Object} Logger
 * @property {function} fatal
 * @property {function} error
 * @property {function} warn
 * @property {function} info
 * @property {function} trace
 */

/**
 * @typedef {Object} TcbComponent
 * @property {number} svn
 * @property {string} [category]
 * @property {string} [type]
 */

/**
 * @typedef {Object} TcbLevel
 *
 * @property {Object} tcb
 * @property {Array.<TcbComponent>} tcb.sgxtcbcomponents - array of 16 SGX TCB Components (as in CPUSVN)
 * @property {Array.<TcbComponent>} [tcb.tdxtcbcomponents] - array of 16 TDX TCB Components (as in TEE TCB SVN array in TD Report)
 * @property {number} tcb.pcesvn - PCS SVN
 * @property {Date} tcbDate - representation of date and time when the TCB level was certified not to be vulnerable
 *                            to any issues described in SAs that were published on or prior to this date.
 *                            The time shall be in UTC and the encoding shall be compliant to
 *                            ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ).
 * @property {string} tcbStatus - TCB level status
 * @property {Array.<string>} [advisoryIDs] - Advisory IDs describing vulnerabilities that this TCB level is vulnerable to
 */

/**
 * @typedef {Object} TdxModule
 * @property {string} mrsigner - base 16 encoded string representation of the measurement of a TDX SEAM module's signer
 * @property {string} attributes - 8 hex-encoded bytes representing attributes golden value
 * @property {string} attributesMask - 8 hex-encoded bytes representing mask to be applied
 *                                     to attributes value retrieved from the platform
 */

/**
 * @typedef {Object} TcbInfo
 * @property {string} id - identified of the TCB Info
 * @property {number} version - version of the structure
 * @property {string} issueDate - representation of date and time the TCB information was created.
 *                                The time shall be in UTC and the encoding shall be compliant to
 *                                ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ).
 * @property {string} nextUpdate - representation of date and time by which next TCB information will be issued.
 *                                 The time shall be in UTC and the encoding shall be compliant to
 *                                 ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ).
 * @property {string} fmspc - base 16-encoded string representation of FMSPC (Family-Model-Stepping-Platform-CustomSKU)
 * @property {string} pceid - base 16-encoded string representation of PCE Identifier
 * @property {number} tcbType - type of TCB level composition
 * @property {number} tcbEvaluationDataNumber - a monotonically increasing sequence number
 *                                              changed when Intel updates the content of the TCB evaluation data set:
 *                                              TCB Info, QE Identity and QVE Identity
 * @property {TdxModule} [tdxModule] - representation of the TDX SEAM module
 * @property {Array.<TcbLevel>} tcbLevels
 */

/**
 * @typedef {Object} EnclaveTcbLevel
 * @property {Object} tcb
 * @property {number} tcb.isvsvn - enclave ISV SVN
 * @property {Date} tcbDate - representation of date and time when the TCB level was certified not to be vulnerable
 *                            to any issues described in SAs that were published on or prior to this date.
 *                            The time shall be in UTC and the encoding shall be compliant to
 *                            ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ).
 * @property {string} tcbStatus - TCB level status
 * @property {Array.<string>} [advisoryIDs] - Advisory IDs describing vulnerabilities that this TCB level is vulnerable to
 */

/**
 * @typedef {Object} EnclaveIdentity
 * @property {string} id - identifier of the enclave
 * @property {number} version - version of the structure
 * @property {string} issueDate - representation of date and time the TCB information was created.
 *                                The time shall be in UTC and the encoding shall be compliant to
 *                                ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ).
 * @property {string} nextUpdate - representation of date and time by which next TCB information will be issued. 
 *                                 The time shall be in UTC and the encoding shall be compliant to
 *                                 ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ).
 * @property {number} tcbEvaluationDataNumber - a monotonically increasing sequence number
 *                                              changed when Intel updates the content of the TCB evaluation data set:
 *                                              TCB Info, QE Identity and QVE Identity
 * @property {string} miscselect - 4 hex-encoded bytes representing miscselect golden value
 * @property {string} miscselectMask - 4 hex-encoded bytes representing mask to be applied
 *                                     to miscselect retrieved from the platform
 * @property {string} attributes - 16 hex-encoded bytes representing attributes golden value
 * @property {string} attributesMask - 16 hex-encoded bytes representing mask to be applied
 *                                     to attributes value retrieved from the platform
 * @property {string} mrsigner - 16 hex-encoded bytes representing mrsigner hash
 * @property {number} isvprodid - enclave product id
 * @property {Array.<EnclaveTcbLevel>} tcbLevels
 */

 module.exports = {};
