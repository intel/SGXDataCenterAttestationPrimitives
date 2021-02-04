export const PLATFORM_REG_SCHEMA = {
  title: 'Platform Registration',
  description: 'Platform Registration Data Format',
  type: 'object',
  properties: {
    qe_id: {
      type: 'string',
      minLength: 1,
      maxLength: 260,
    },
    pce_id: {
      type: 'string',
      pattern: '^[a-fA-F0-9]{4}$',
    },
    cpu_svn: {
      type: 'string',
      pattern: '^[a-fA-F0-9]{32}$',
    },
    pce_svn: {
      type: 'string',
      pattern: '^[a-fA-F0-9]{4}$',
    },
    enc_ppid: {
      type: 'string',
      pattern: '^[a-fA-F0-9]{768}$',
    },
    platform_manifest: {
      type: 'string',
    },
  },
  required: ['qe_id', 'pce_id'],
};

export const PLATFORM_COLLATERAL_SCHEMA = {
  title: 'Platform Registration',
  description: 'Platform Registration Data Format',
  type: 'object',
  properties: {
    platforms: {
      type: 'array',
      items: {
        'type:': 'object',
        properties: {
          qe_id: {
            type: 'string',
            minLength: 1,
            maxLength: 260,
          },
          pce_id: {
            type: 'string',
            pattern: '^[a-fA-F0-9]{4}$',
          },
          cpu_svn: {
            type: 'string',
            pattern: '^[a-fA-F0-9]{32}$|^$',
          },
          pce_svn: {
            type: 'string',
            pattern: '^[a-fA-F0-9]{4}$|^$',
          },
          enc_ppid: {
            type: 'string',
            pattern: '^[a-fA-F0-9]{768}$|^$',
          },
          platform_manifest: {
            type: 'string',
          },
        },
        required: ['qe_id', 'pce_id'],
      },
    },
    collaterals: {
      type: 'object',
      properties: {
        pck_certs: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              qe_id: {
                type: 'string',
                minLength: 1,
                maxLength: 260,
              },
              pce_id: {
                type: 'string',
                pattern: '^[a-fA-F0-9]{4}$',
              },
              enc_ppid: {
                type: 'string',
                pattern: '^[a-fA-F0-9]{768}$|^$',
              },
              platform_manifest: {
                type: 'string',
              },
              certs: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    tcb: {
                      type: 'object',
                      properties: {
                        sgxtcbcomp01svn: {
                          type: 'integer',
                          minimum: 0,
                          maximum: 255,
                        },
                        sgxtcbcomp02svn: {
                          type: 'integer',
                          minimum: 0,
                          maximum: 255,
                        },
                        sgxtcbcomp03svn: {
                          type: 'integer',
                          minimum: 0,
                          maximum: 255,
                        },
                        sgxtcbcomp04svn: {
                          type: 'integer',
                          minimum: 0,
                          maximum: 255,
                        },
                        sgxtcbcomp05svn: {
                          type: 'integer',
                          minimum: 0,
                          maximum: 255,
                        },
                        sgxtcbcomp06svn: {
                          type: 'integer',
                          minimum: 0,
                          maximum: 255,
                        },
                        sgxtcbcomp07svn: {
                          type: 'integer',
                          minimum: 0,
                          maximum: 255,
                        },
                        sgxtcbcomp08svn: {
                          type: 'integer',
                          minimum: 0,
                          maximum: 255,
                        },
                        sgxtcbcomp09svn: {
                          type: 'integer',
                          minimum: 0,
                          maximum: 255,
                        },
                        sgxtcbcomp10svn: {
                          type: 'integer',
                          minimum: 0,
                          maximum: 255,
                        },
                        sgxtcbcomp11svn: {
                          type: 'integer',
                          minimum: 0,
                          maximum: 255,
                        },
                        sgxtcbcomp12svn: {
                          type: 'integer',
                          minimum: 0,
                          maximum: 255,
                        },
                        sgxtcbcomp13svn: {
                          type: 'integer',
                          minimum: 0,
                          maximum: 255,
                        },
                        sgxtcbcomp14svn: {
                          type: 'integer',
                          minimum: 0,
                          maximum: 255,
                        },
                        sgxtcbcomp15svn: {
                          type: 'integer',
                          minimum: 0,
                          maximum: 255,
                        },
                        sgxtcbcomp16svn: {
                          type: 'integer',
                          minimum: 0,
                          maximum: 255,
                        },
                        pcesvn: {
                          type: 'integer',
                          minimum: 0,
                          maximum: 65535,
                        },
                      },
                    },
                    tcbm: {
                      type: 'string',
                      pattern: '^[0-9a-fA-F]{36}$',
                    },
                    cert: {
                      type: 'string',
                    },
                  },
                  required: ['tcb', 'tcbm', 'cert'],
                },
              },
            },
            required: ['qe_id', 'pce_id', 'enc_ppid', 'certs'],
          },
        },
        tcbinfos: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              fmspc: {
                type: 'string',
              },
              tcbinfo: {
                type: 'object',
                properties: {
                  tcbInfo: {
                    type: 'object',
                    properties: {
                      version: {
                        type: 'integer',
                      },
                      issueDate: {
                        type: 'string',
                        format: 'date-time',
                      },
                      nextUpdate: {
                        type: 'string',
                        format: 'date-time',
                      },
                      fmspc: {
                        type: 'string',
                        pattern: '^[0-9a-fA-F]{12}$',
                      },
                      pceId: {
                        type: 'string',
                        pattern: '^[0-9a-fA-F]{4}$',
                      },
                      tcbType: {
                        type: 'integer',
                      },
                      tcbEvaluationDataNumber: {
                        type: 'integer',
                      },
                      tcbLevels: {
                        type: 'array',
                        items: {
                          type: 'object',
                          properties: {
                            tcb: {
                              type: 'object',
                              properties: {
                                pcesvn: {
                                  type: 'integer',
                                },
                                sgxtcbcomp01svn: {
                                  type: 'integer',
                                  minimum: 0,
                                  maximum: 255,
                                },
                                sgxtcbcomp02svn: {
                                  type: 'integer',
                                  minimum: 0,
                                  maximum: 255,
                                },
                                sgxtcbcomp03svn: {
                                  type: 'integer',
                                  minimum: 0,
                                  maximum: 255,
                                },
                                sgxtcbcomp04svn: {
                                  type: 'integer',
                                  minimum: 0,
                                  maximum: 255,
                                },
                                sgxtcbcomp05svn: {
                                  type: 'integer',
                                  minimum: 0,
                                  maximum: 255,
                                },
                                sgxtcbcomp06svn: {
                                  type: 'integer',
                                  minimum: 0,
                                  maximum: 255,
                                },
                                sgxtcbcomp07svn: {
                                  type: 'integer',
                                  minimum: 0,
                                  maximum: 255,
                                },
                                sgxtcbcomp08svn: {
                                  type: 'integer',
                                  minimum: 0,
                                  maximum: 255,
                                },
                                sgxtcbcomp09svn: {
                                  type: 'integer',
                                  minimum: 0,
                                  maximum: 255,
                                },
                                sgxtcbcomp10svn: {
                                  type: 'integer',
                                  minimum: 0,
                                  maximum: 255,
                                },
                                sgxtcbcomp11svn: {
                                  type: 'integer',
                                  minimum: 0,
                                  maximum: 255,
                                },
                                sgxtcbcomp12svn: {
                                  type: 'integer',
                                  minimum: 0,
                                  maximum: 255,
                                },
                                sgxtcbcomp13svn: {
                                  type: 'integer',
                                  minimum: 0,
                                  maximum: 255,
                                },
                                sgxtcbcomp14svn: {
                                  type: 'integer',
                                  minimum: 0,
                                  maximum: 255,
                                },
                                sgxtcbcomp15svn: {
                                  type: 'integer',
                                  minimum: 0,
                                  maximum: 255,
                                },
                                sgxtcbcomp16svn: {
                                  type: 'integer',
                                  minimum: 0,
                                  maximum: 255,
                                },
                              },
                            },
                            tcbDate: {
                              type: 'string',
                              format: 'date-time',
                            },
                            tcbStatus: {
                              type: 'string',
                            },
                            advisoryIDs: {
                              type: 'array',
                              items: {
                                type: 'string',
                              },
                            },
                          },
                        },
                      },
                    },
                  },
                  signature: {
                    type: 'string',
                  },
                },
                required: ['tcbInfo', 'signature'],
              },
            },
            required: ['fmspc', 'tcbinfo'],
          },
        },
        pckcacrl: {
          type: 'object',
          properties: {
            processorCrl: {
              type: 'string',
            },
            platformCrl: {
              type: 'string',
            },
          },
        },
        qeidentity: {
          type: 'string',
        },
        qveidentity: {
          type: 'string',
        },
        certificates: {
          type: 'object',
          properties: {
            'SGX-PCK-Certificate-Issuer-Chain': {
              type: 'object',
              properties: {
                PROCESSOR: {
                  type: 'string',
                },
                PLATFORM: {
                  type: 'string',
                },
              },
            },
            'SGX-TCB-Info-Issuer-Chain': {
              type: 'string',
            },
            'SGX-Enclave-Identity-Issuer-Chain': {
              type: 'string',
            },
          },
          required: ['SGX-PCK-Certificate-Issuer-Chain'],
        },
        rootcacrl: {
          type: 'string',
        },
      },
      required: ['pck_certs', 'tcbinfos', 'certificates'],
    },
  },
  required: ['platforms', 'collaterals'],
};
