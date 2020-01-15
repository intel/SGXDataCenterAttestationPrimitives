Administrator tool for PCCS

Prerequisites
  Install python3 and pip3 first, then install required packages using pip3
    sudo apt install python3
    sudo apt install python3-pip
    pip3 install -r requirements.txt


Usage: ./pccsadmin.py [-h] {get,put,fetch} ...

positional arguments:
  {get,put,fetch}

optional arguments:
  -h, --help       show this help message and exit


1. Get registration data from PCCS service
  ./pccsadmin.py get [-h] [-u URL] [-o OUTPUT_FILE] [-s SOURCE] -t TOKEN

  optional arguments:
          -h, --help            show this help message and exit
          -u URL, --url URL     The URL of the PCCS service. If omitted, "https://localhost:8081" will be used.
          -o OUTPUT_FILE, --output_file OUTPUT_FILE
                                The output file name for platform list. If omitted, "platform_list.json" will be used.
          -s SOURCE, --source SOURCE
                                reg - Get platforms from registration table.(default)
                                [FMSPC1,FMSPC2,...] - Get platforms from cache based on the fmspc values. [] to get all cached platforms.
          -t TOKEN, --token TOKEN
                                Administrator token for PCCS


2. Fetch platform collateral data from Intel PCS based on the registration data
  ./pccsadmin.py fetch [-h] [-i INPUT_FILE] [-o OUTPUT_FILE] -k KEY

  optional arguments:
          -h, --help            show this help message and exit
          -i INPUT_FILE, --input_file INPUT_FILE
                                The input file name for platform list. If omitted, "platform_list.json" will be used.
          -o OUTPUT_FILE, --output_file OUTPUT_FILE
                                The output file name for platform collaterals. If omitted, "platform_collaterals.json" will be used.
          -k KEY, --key KEY     Your Intel PCS API key


3. Put platform collateral data to PCCS cache db 
  ./pccsadmin.py put [-h] [-u URL] [-i INPUT_FILE] -t TOKEN

  optional arguments:
          -h, --help            show this help message and exit
          -u URL, --url URL     The URL of the PCCS service. If omitted, "https://api.trustedservices.intel.com/sgx/certification" will be used.
          -i INPUT_FILE, --input_file INPUT_FILE
                                The input file name for platform collaterals. If omitted, "platform_collaterals.json" will be used.
          -t TOKEN, --token TOKEN
                                Administrator token for PCCS

