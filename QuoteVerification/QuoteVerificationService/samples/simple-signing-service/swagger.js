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

const swaggerAutogen = require('swagger-autogen')();

const outputFile = './swagger.json';
const endpointsFiles = ['./simple-signing-service.js'];

const doc = {
  info: {
    version:     '1.0.0',
    title:       'Simple Signing Service',
    description: 'Documentation automatically generated from comments in SSS code'
  },
  host:        'localhost:8797',
  basePath:    '/',
  schemes:     ['https'],
  consumes:    ['application/json'],
  produces:    ['application/json'],
  definitions: {
    PositiveHealthReport: {
      status:      'OK',
      version:     '1.0.0',
      lastChecked: '2023-03-07T10:30:29.282Z'
    },
    NegativeHealthReport: {
      status:      'FAILED',
      version:     '1.0.0',
      lastChecked: '2023-03-07T10:30:29.282Z'
    },
    SignatureResponse: {
      signature: 'M5iPd/7XrQlhweDBzKzou8kIamLAfDR/Hc1bC8RCEtxpDLlRhRWjxlUNpIwcDoxvRSt7fMQujO4JPaTV9+bTW3b74rhSmkiuTdxMnF7eYZl29cge6OFCpyz9M/c4U61IlYE8yAFoaSrbd0zHH0jUx//AzsD1Iw03P8YL2G/rUbBAtOGpZUF7hRmHDVGqGhjN6n0HIX4yMZ8CHQQTTziJokn+HSIN8tDQWV5DVFfCLFmUQ5Fyf3UIh07FmX+3HDukR/601FvbBvoaw3ERTjtLH30d+3Px/EVq8ZwRy6SCE9+3MJpIXFZttL4wO45mNEiHNdMPnBTBPJylN2a5mkz1Ww=='
    }
  }
};

swaggerAutogen(outputFile, endpointsFiles, doc);
