#!/usr/bin/env python3
# encoding: utf-8

import argparse
import requests
import os
import csv
import json
import re
import struct
import time
from lib.intelsgx.pckcert import SgxPckCertificateExtensions
from lib.intelsgx.pcs import PCS
from lib.intelsgx.credential import Credentials
from urllib.parse import unquote
import traceback

PCS_SERVICE_URL = 'https://api.trustedservices.intel.com/sgx/certification/v4/'
PCCS_SERVICE_URL = 'https://localhost:8081/sgx/certification/v4'

def main():
    parser = argparse.ArgumentParser(description="Administrator tool for PCCS")
    #parser.add_argument('action', help='Choose your action')
    subparsers = parser.add_subparsers(dest="command")

    #  subparser for get
    parser_get = subparsers.add_parser('get', formatter_class=argparse.RawTextHelpFormatter)
    # add optional arguments for get
    parser_get.add_argument("-u", "--url", help="The URL of the PCCS's GET platforms API; default: https://localhost:8081/sgx/certification/v4/platforms")
    parser_get.add_argument("-o", "--output_file", help="The output file name for platform list; default: platform_list.json")
    parser_get.add_argument("-s", "--source", help=
              "reg - Get platforms from registration table.(default)\n"
              "reg_na - Get platforms whose PCK certs are currently not available from registration table.\n"
            + "[FMSPC1,FMSPC2,...] - Get platforms from cache based on the fmspc values. [] to get all cached platforms.")
    parser_get.set_defaults(func=pccs_get)

    #  subparser for put
    description_put = (
    "This put command supports the following formats([] means optional):\n"
    "1. pccsadmin put [-u https://localhost:8081/sgx/certification/v4/platformcollateral] [-i collateral_file(*.json)]\n"
    "2. pccsamdin put -u https://localhost:8081/sgx/certification/v4/appraisalpolicy [-d] -f fmspc -i policy_file(*.jwt)"
    )
    parser_put = subparsers.add_parser('put', description=description_put, formatter_class=argparse.RawTextHelpFormatter)
    # add optional arguments for put
    parser_put.add_argument("-u", "--url", help="The URL of the PCCS's API; default: https://localhost:8081/sgx/certification/v4/platformcollateral")
    parser_put.add_argument("-i", "--input_file", help="The input file name for platform collaterals or appraisal policy;\
                            \nFor /platformcollateral API, default is platform_collaterals.json;\
                            \nFor /appraisalpolicy API, the filename of the jwt file must be provided explicitly.")
    parser_put.add_argument("-d", "--default", help="This policy will become the default policy for this FMSPC.", action="store_true")
    parser_put.add_argument('-f', '--fmspc', type=str, help="FMSPC value")
    parser_put.set_defaults(func=pccs_put)

    #  subparser for fetch
    parser_fetch = subparsers.add_parser('fetch')
    # add optional arguments for fetch
    parser_fetch.add_argument("-u", "--url", help="The URL of the Intel PCS service; default: https://api.trustedservices.intel.com/sgx/certification/v4/")
    parser_fetch.add_argument("-i", "--input_file", help="The input file name for platform list; default: platform_list.json")
    parser_fetch.add_argument("-o", "--output_file", help="The output file name for platform collaterals; default: platform_collaterals.json")
    parser_fetch.add_argument("-p", "--platform", help="Specify what kind of platform you want to fetch FMSPCs and tcbinfos for; default: all", choices=['all','client','E3','E5'])
    parser_fetch.add_argument("-t", "--tcb_update_type", help="Type of update to TCB info and enclave identities; default: standard", choices=['standard','early','all'])
    parser_fetch.add_argument("-c", "--crl", help="Retrieve only the certificate revocation list (CRL). If an input file is provided, this option will be ignored.", action="store_true")
    parser_fetch.set_defaults(func=pcs_fetch)

    #  subparser for collect 
    parser_collect = subparsers.add_parser('collect')
    # add optional arguments for collect
    parser_collect.add_argument("-d", "--directory", help="The directory where platform CSV files are saved; default: ./")
    parser_collect.add_argument("-o", "--output_file", help="The output file name for platform list; default: platform_list.json")
    parser_collect.set_defaults(func=collect_platforms)

    #  subparser for refresh
    parser_refresh = subparsers.add_parser('refresh')
    # add optional arguments for refresh
    parser_refresh.add_argument("-u", "--url", help="The URL of the PCCS's refresh API; default: https://localhost:8081/sgx/certification/v4/refresh")
    parser_refresh.add_argument("-f", "--fmspc", help="Only refresh certificates for specified FMSPCs. Format: [FMSPC1, FMSPC2, ..., FMSPCn]")
    parser_refresh.set_defaults(func=pccs_refresh)

    #  subparser for cache
    parser_cache = subparsers.add_parser('cache')
    # add optional arguments for cache
    parser_cache.add_argument("-u", "--url", help="The URL of the Intel PCS service; default: https://api.trustedservices.intel.com/sgx/certification/v4/")
    parser_cache.add_argument("-i", "--input_file", help="The input file name for platform list; default: platform_list.csv")
    parser_cache.add_argument("-o", "--output_dir", help="The destination directory for storing the generated cache files")
    parser_cache.add_argument("-s", "--sub_dir", help="Store output cache files in subdirectories named according to QE ID or Platform ID", action="store_true")
    parser_cache.add_argument("-e", "--expire", type=Utils.check_expire_hours, help="How many hours the cache files will be valid for. Default is 2160 hours (90 days).")
    parser_cache.set_defaults(func=pcs_cache)

    args = parser.parse_args()
    if len(args.__dict__) <= 1:
        # No arguments or subcommands were given.
        parser.print_help()
        parser.exit()

    print(args)
    # Check mandatory arguments for appraisalpolicy
    if args.command == 'put' and args.url and args.url.endswith("/appraisalpolicy"):
        if not args.fmspc or not args.input_file:
            parser.error("For putting appraisal policy, -f/--fmspc and -i/--input_file are mandatory.")

    args.func(args)

class Utils:
    @staticmethod
    def check_expire_hours(value):
        try:
            int_value = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{value} is not a valid integer")

        if 0 <= int_value <= 8760:
            return int_value
        else:
            raise argparse.ArgumentTypeError(f"{value} is not in the range [0, 8760]")

    @staticmethod
    def check_file_writable(filename):
        fullpath = os.path.join(os.getcwd(), filename)
        if os.path.isfile(fullpath):
            while True:
                overwrite = input('File %s already exists. Overwrite? (y/n) ' %(filename))
                if overwrite.lower() == "y":
                    break
                if overwrite.lower() == "n":
                    print("Aborted.")
                    return False
        return True

    @staticmethod
    def get_api_version_from_url(url):
        version = 4
        regex = re.compile('/v[1-9][0-9]*/')
        match = regex.search(url)
        if match is not None:
            verstr = match[0]
            if len(verstr) >= 4:
                version = int(verstr[2:-1])
        return version           

class PccsClient:
    BASE_URL = PCCS_SERVICE_URL
    GET_URL = BASE_URL + "/platforms"
    PUT_URL = BASE_URL + "/platformcollateral"
    REFRESH_URL = BASE_URL + "/refresh"
    OUTPUT_FILE = "platform_list.json"
    INPUT_FILE = "platform_collaterals.json"
    USER_AGENT = 'pccsadmin/0.1'
    CONTENT_TYPE = 'application/json'
    FMSPC = None
    
    def __init__(self, credentials, args):
        self.credentials = credentials
        self.args = args

    def get_platforms(self):
        try:
            url = self.args.url or self.GET_URL
            output_file = self.args.output_file or self.OUTPUT_FILE
            if self.args.source:
                url += '?source=' + self.args.source

            token = self.credentials.get_admin_token()
            headers = {'user-agent': self.USER_AGENT, 'admin-token': token}
            params = {}
            response = requests.get(url=url, headers=headers, params=params, verify=False)

            if response.status_code == 200:
                self._write_output_file(output_file, response)
            elif response.status_code == 401:  # Authentication error
                self.credentials.set_admin_token('')
                print("Authentication failed.")
            else:
                self._handle_error(response)

        except Exception as e:
            print(e)

    def upload_collaterals(self):
        try:
            url = self.args.url or self.PUT_URL
            input_file = self.args.input_file or self.INPUT_FILE

            token = self.credentials.get_admin_token()
            headers = {
                'user-agent': self.USER_AGENT,
                'Content-Type': self.CONTENT_TYPE,
                'admin-token': token
            }
            params = {}
            fullpath = os.path.join(os.getcwd(), input_file)
            with open(fullpath) as inputfile:
                data = inputfile.read()

            if url.endswith("/platformcollateral"):
                response = requests.put(url=url, data=data, headers=headers, params=params, verify=False)

                if response.status_code == 200:
                    print("Collaterals uploaded successfully.")
                elif response.status_code == 401:  # Authentication error
                    self.credentials.set_admin_token('')
                    print("Authentication failed.")
                else:
                    self._handle_error(response)
            elif url.endswith("/appraisalpolicy"):
                appraisal_policy = {
                    "policy": data,
                    "is_default": self.args.default,
                    "fmspc": self.args.fmspc,
                }
                # Convert the dictionary to a JSON string
                data_str = json.dumps(appraisal_policy)
                response = requests.put(url=url, data=data_str, headers=headers, params=params, verify=False)
                if response.status_code == 200:
                    print("Policy uploaded successfully with policy ID :" + response.text)
                elif response.status_code == 401:  # Authentication error
                    self.credentials.set_admin_token('')
                    print("Authentication failed.")
                else:
                    self._handle_error(response)
            else:
                print("Invalid URL.")

        except Exception as e:
            print(e)

    def refresh_cache_database(self):
        try:
            url = self.args.url or self.REFRESH_URL
            fmspc = self.args.fmspc or self.FMSPC
            # Get administrator token from keyring
            token = self.credentials.get_admin_token()
            # Prepare headers and params for request
            headers = {
                'user-agent': self.USER_AGENT,
                'admin-token': token
            }
            params = {}
            if fmspc == 'all':
                params = {'type': 'certs',
                        'fmspc':''}
            elif fmspc != None:
                params = {'type': 'certs',
                        'fmspc': fmspc}
                
            response = requests.post(url=url, headers=headers, params=params, verify=False)
            if response.status_code == 200:
                print("The cache database was refreshed successfully.")
            elif response.status_code == 401:  # Authentication error
                self.credentials.set_admin_token('')
                print("Authentication failed.")
            else:
                self._handle_error(response)

        except Exception as e:
            print(e)

    @staticmethod
    def _write_output_file(output_file, response):
        if Utils.check_file_writable(output_file):
            with open(output_file, "w") as ofile:
                json.dump(response.json(), ofile)
            print(output_file, " saved successfully.")

    @staticmethod
    def _handle_error(response):
        print("Failed to interact with the PCCS.")
        print("\tStatus code is : %d" % response.status_code)
        print("\tMessage : ", response.text)

class PlatformCollector:
    def __init__(self, args):
        self.csv_dir = args.directory or '.'
        self.output_file = args.output_file or "platform_list.json"
        self.fieldnames = ("enc_ppid", "pce_id", "cpu_svn", "pce_svn", "qe_id", "platform_manifest")
        self.platform_list = []

    def collect(self):
        try:
            if not Utils.check_file_writable(self.output_file):
                return

            arr = os.listdir(self.csv_dir)
            if len(arr) < 2:
                print("At least 2 csv files are needed. Please make sure this is an administrator platform.")
                return

            self.read_csv_files(arr)
            self.write_to_json()
            print(self.output_file, " saved successfully.")

        except Exception as e:
            print(e)
            traceback.print_exc()

    def read_csv_files(self, arr):
        for file in arr:
            if file.endswith(".csv"):
                with open(os.path.join(self.csv_dir, file), 'r') as csvfile:
                    reader = csv.DictReader(csvfile, self.fieldnames)
                    self.platform_list.extend(row for row in reader)

    def write_to_json(self):
        with open(self.output_file, 'w') as jsonfile:
            json.dump(self.platform_list, jsonfile)

class CollateralFetcher:
    def __init__(self, credentials, args):
        self.credentials = credentials
        self.args = args
        self.url = args.url or PCS_SERVICE_URL
        self.ApiVersion = Utils.get_api_version_from_url(self.url)
        self.input_file = args.input_file or 'platform_list.json'
        self.output_file = args.output_file or 'platform_collaterals.json'
        self.fmspc_platform = args.platform or 'all'
        self.tcb_update_type = args.tcb_update_type or 'standard'
        self.crl_only = bool(args.crl and not args.input_file)
        self.apikey = ""
        if not self.crl_only:
            self.apikey = self.credentials.get_pcs_api_key()
        self.pcsclient = PCS(self.url, self.ApiVersion, self.apikey)
        self.sgxext = SgxPckCertificateExtensions()
        self.output_json = self._init_output_data()
        self.fmspc_set = set()

    def fetch_collateral(self):
        try:
            if not Utils.check_file_writable(self.output_file):
                return
            if not self._fetch_pck_crl_and_root_ca_crl():
                return
            if self.crl_only:
                self._write_output_json()
                return
            self._load_platform_list()
            if not self._fetch_pck_certs():
                return
            if not self._fetch_tcbinfos():
                return
            if not self._fetch_identity('qe'):
                return
            if self.ApiVersion >= 4:
                if not self._fetch_identity('tdqe'):
                    return
            if not self._fetch_identity('qve'):
                return
            self._write_output_json()
        except Exception as e:
            print(e)
            traceback.print_exc()

    def _init_output_data(self):
        output_json = {}
        output_json["platforms"] = []
        output_json["collaterals"] = { 
            "version": self.ApiVersion,
            "pck_certs" : [],
            "tcbinfos" : [],
            "pckcacrl" : {},
            "qeidentity" : "",
            "tdqeidentity" : "",
            "qveidentity" : "",
            "certificates" : {
                PCS.HDR_PCK_Certificate_Issuer_Chain: {},
                PCS.HDR_TCB_INFO_ISSUER_CHAIN: "",
                PCS.HDR_Enclave_Identity_Issuer_Chain : ""
            },
            "rootcacrl": ""
        }
        return output_json

    def _fetch_pck_crl_and_root_ca_crl(self):
        processorCrl = self.pcsclient.get_pck_crl('processor', 'ascii')
        if processorCrl == None:
            print("Failed to get processor PCK CRL.")
            return False
        self.output_json["collaterals"]["pckcacrl"]["processorCrl"] = processorCrl[0]

        if self.ApiVersion >= 3:
            platformCrl = self.pcsclient.get_pck_crl('platform', 'ascii')
            if platformCrl == None:
                print("Failed to get platform PCK CRL.")
                return False
            self.output_json["collaterals"]["pckcacrl"]["platformCrl"] = platformCrl[0]

        # output.collaterals.rootcacrl
        spos = processorCrl[1].rfind('-----BEGIN%20CERTIFICATE-----')
        root_cert = processorCrl[1][spos:]
        cdp = self.sgxext.get_root_ca_crl(unquote(root_cert).encode('utf-8'))
        rootcacrl = self.pcsclient.getFileFromUrl(cdp)
        self.output_json["collaterals"]["rootcacrl_cdp"] = cdp
        self.output_json["collaterals"]["rootcacrl"] = rootcacrl
        return True

    def _load_platform_list(self):
        input_fullpath = os.path.join(os.getcwd(), self.input_file)
        with open(input_fullpath) as ifile:
            platformlist = json.load(ifile)
            self.output_json["platforms"] = platformlist

    def _fetch_pck_certs(self):
        platform_dict = {}
        for platform in self.output_json["platforms"]:
            platform_dict[(platform["qe_id"], platform["pce_id"])] = {"enc_ppid" : platform["enc_ppid"], 
                                                                    "platform_manifest" : platform["platform_manifest"]}
        certs_not_available = []
        for platform_id in platform_dict:
            enc_ppid = platform_dict[platform_id]["enc_ppid"]
            platform_manifest = platform_dict[platform_id]["platform_manifest"]
            pce_id = platform_id[1]

            # get pckcerts from Intel PCS, return value is [certs, certs_not_available, chain, fmspc]
            pckcerts = self.pcsclient.get_pck_certs(enc_ppid, pce_id, platform_manifest, 'ascii')
            if pckcerts == None:
                print("Failed to get PCK certs for platform enc_ppid:%s, pce_id:%s" %(enc_ppid,pce_id))
                return False

            # Get the first property
            pckcerts_json = pckcerts[0]

            # parse the first cert to get FMSPC value and put it into a set
            cert = pckcerts_json[0]["cert"]
            self.sgxext.parse_pem_certificate(unquote(cert).encode('utf-8'))
            self.fmspc_set.add(self.sgxext.get_fmspc())

            # set pck-certificate-issuer-chain
            ca = self.sgxext.get_ca()
            if ca is None:
                print("Wrong PCK certificate format!")
                return False

            pckchain = self.output_json["collaterals"]["certificates"][PCS.HDR_PCK_Certificate_Issuer_Chain]
            if not hasattr(pckchain, ca) or pckchain[ca] == '':
                pckchain[ca] = pckcerts[2]

            self.output_json["collaterals"]["pck_certs"].append({
                "qe_id" : platform_id[0],
                "pce_id" : pce_id,
                "enc_ppid": enc_ppid,
                "platform_manifest": platform_dict[platform_id]["platform_manifest"],
                "certs": pckcerts_json
            })
            certs_not_available.extend(pckcerts[1])

        if len(certs_not_available) > 0:
            # Found 'Not available' platforms
            while True:
                save_to_file = input("Some certificates are 'Not available'. Do you want to save the list?(y/n)")
                if save_to_file.lower() == "y":
                    file_na = input("Please input file name (Press enter to use default name not_available.json):")
                    if file_na.strip() == '' :
                        file_na = 'not_available.json'
                    # write output file
                    if Utils.check_file_writable(file_na):
                        with open(file_na, "w") as ofile:
                            json.dump(certs_not_available, ofile)
                        print("Please check " + file_na + " for 'Not available' certificates.")
                    else:
                        print('Unable to save file. ')

                    break
                if save_to_file.lower() == "n":
                    break
        return True

    def _fetch_tcbinfos(self):
        # Get fmspcs for specified platform
        fmspcs = self.pcsclient.get_fmspcs(self.fmspc_platform, 'ascii')
        if fmspcs != None:
            for fmspc in fmspcs:
                self.fmspc_set.add(fmspc['fmspc'])

        updates = ['standard', 'early'] if self.tcb_update_type == 'all' else [self.tcb_update_type]
        # output.collaterals.tcbinfos
        for fmspc in self.fmspc_set:
            tcbinfoJson = {"fmspc" : fmspc}
            for update in updates:
                # tcbinfo : [tcbinfo, chain]
                sgx_tcbinfo = self.pcsclient.get_tcb_info(fmspc, 'sgx', update, 'ascii')

                if sgx_tcbinfo is None:
                    if update == 'standard':
                        print(f"Failed to get SGXtcbinfo for FMSPC:{fmspc}")
                        return False
                    continue

                # Handling different keys based on update type and ApiVersion
                key_suffix = '_early' if update == 'early' else ''
                if self.ApiVersion >= 4:
                    tcbinfo_key = f'sgx_tcbinfo{key_suffix}'
                else:
                    tcbinfo_key = f'tcbinfo{key_suffix}'

                tcbinfoJson[tcbinfo_key] = json.loads(sgx_tcbinfo[0])

                # TDX tcbinfo is optional
                if self.ApiVersion >= 4:
                    tdx_tcbinfo = self.pcsclient.get_tcb_info(fmspc, 'tdx', update, 'ascii')
                    if tdx_tcbinfo is not None:
                        tdx_tcbinfo_key = f'tdx_tcbinfo{key_suffix}'
                        tcbinfoJson[tdx_tcbinfo_key] = json.loads(tdx_tcbinfo[0])
                # End loop

            self.output_json["collaterals"]["tcbinfos"].append(tcbinfoJson)
            if not self.output_json["collaterals"]["certificates"][PCS.HDR_TCB_INFO_ISSUER_CHAIN]:
                self.output_json["collaterals"]["certificates"][PCS.HDR_TCB_INFO_ISSUER_CHAIN] = sgx_tcbinfo[1]
        return True

    def _fetch_identity(self, identity_type):
        updates = ['standard', 'early'] if self.tcb_update_type == 'all' else [self.tcb_update_type]
        for update in updates:
            identity = self.pcsclient.get_enclave_identity(identity_type, update, 'ascii')
            if identity is None:
                if update == 'standard':
                    print(f"Failed to get {identity_type.upper()} identity")
                    return False
            else:
                key_suffix = '_early' if update == 'early' else ''
                self.output_json["collaterals"][f"{identity_type}identity{key_suffix}"] = identity[0]
                if identity_type == 'qe':
                    self.output_json["collaterals"]["certificates"][PCS.HDR_Enclave_Identity_Issuer_Chain] = identity[1]
        return True

    def _write_output_json(self):
        with open(self.output_file, "w") as ofile:
            json.dump(self.output_json, ofile)
        print(self.output_file, " saved successfully.")

class CacheCreator:
    DEFAULT_TCBCOMPONENT = "ffffffffffffffffffffffffffffffff"

    def __init__(self, credentials, args):
        self.credentials = credentials
        self.args = args
        self.sub_dir = bool(args.sub_dir)

    @staticmethod
    def _decompose_cpusvn_components(cpusvn: str, tcb_type: int) -> str:
        if tcb_type == 0:
            if cpusvn:
                return cpusvn
            else:
                return CacheCreator.DEFAULT_TCBCOMPONENT
        else:
            raise ValueError("Unsupported TCB type.")

    @staticmethod
    def _write_to_file(file, data):
        file.write(struct.pack("I", len(data)))
        file.write(data.encode("utf-8"))

    def write_to_cache_file(self, platform, output_dir, expire_hours, tcbcomponent, sgx_tcbinfo, pckcerts):
        SGX_QPL_CACHE_MULTICERTS = 1 << 2
        cache_item_header = struct.pack('<HIQ', 1, SGX_QPL_CACHE_MULTICERTS, int(time.time() + expire_hours * 60 * 60))
        cache_file_dir = output_dir
        if self.sub_dir:
            cache_file_dir = os.path.join(output_dir, platform["qe_id"])
            if not os.path.exists(cache_file_dir):
                os.makedirs(cache_file_dir)
        if tcbcomponent == CacheCreator.DEFAULT_TCBCOMPONENT:
            output_file = os.path.join(cache_file_dir, "0000000000000000_0000")
        else:
            output_file = os.path.join(cache_file_dir, (platform["qe_id"] + "_" + platform["pce_id"]).lower())

        with open(output_file, "wb") as ofile:
            # Write cache header
            ofile.write(cache_item_header)
            # Write TCB component
            self._write_to_file(ofile, tcbcomponent)
            # Write TCB info
            self._write_to_file(ofile, sgx_tcbinfo[0])
            # Write Certchain
            self._write_to_file(ofile, pckcerts[2])
            # Write PCK certificates
            certs_string = json.dumps(pckcerts[0])
            self._write_to_file(ofile, certs_string)
            print(f"{output_file} saved successfully.")

    def create_platform_cache_file(self, platform, pcsclient, output_dir, expire_hours):
        pckcerts = pcsclient.get_pck_certs(platform["enc_ppid"], platform["pce_id"], platform["platform_manifest"], 'ascii')

        if pckcerts is None:
            print(f"Failed to get PCK certs for platform enc_ppid: {platform['enc_ppid']}, pce_id: {platform['pce_id']}")
            return False

        fmspc = pckcerts[3]
        sgx_tcbinfo = pcsclient.get_tcb_info(fmspc, 'sgx', 'ascii')
        tcbcomponent = self._decompose_cpusvn_components(platform["cpu_svn"], json.loads(sgx_tcbinfo[0])["tcbInfo"]["tcbType"])
        self.write_to_cache_file(platform, output_dir, expire_hours, tcbcomponent, sgx_tcbinfo, pckcerts)
        return True
    
    def generate_cache(self):
        url = self.args.url or PCS_SERVICE_URL
        ApiVersion = Utils.get_api_version_from_url(url)
        input_file = self.args.input_file or 'platform_list.json'
        output_dir = self.args.output_dir or './cache/'
        expire_hours = int(self.args.expire or 2160)

        try :
            input_fullpath = os.path.join(os.getcwd(), input_file)

            # Get PCS ApiKey from keyring
            apikey = self.credentials.get_pcs_api_key()

            # Initialize PCS object
            pcsclient = PCS(url, ApiVersion, apikey)

            with open(input_fullpath) as ifile:
                plaformlist = json.load(ifile)

            # Check if output directory exists. Create it if it doesn't.
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)

            for platform in plaformlist:
                if not self.create_platform_cache_file(platform, pcsclient, output_dir, expire_hours):
                    return

        except Exception as e:
            print(e)
            traceback.print_exc()

def pccs_get(args):
    credentials = Credentials()
    client = PccsClient(credentials, args)
    client.get_platforms()

def pccs_put(args):
    credentials = Credentials()
    client = PccsClient(credentials, args)
    client.upload_collaterals()

def pccs_refresh(args):
    credentials = Credentials()
    client = PccsClient(credentials, args)
    client.refresh_cache_database()

def collect_platforms(args):
    collector = PlatformCollector(args)
    collector.collect()

def pcs_fetch(args):
    credentials = Credentials()
    pcsWrapper = CollateralFetcher(credentials, args)
    pcsWrapper.fetch_collateral()

def pcs_cache(args):
    credentials = Credentials()
    pcsWrapper = CacheCreator(credentials, args)
    pcsWrapper.generate_cache()

main()
