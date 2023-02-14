rm -f test_jwt_qal test_jwt_qal_local test_jwt_qvl

g++ -g -O0 -o test_jwt_qal test_jwt.cpp -I $SGX_SDK/include  -I../ -I../../../../external/jwt-cpp/include -L ../ -lsgx_dcap_qal -lpthread

#g++ -g -O0 -o test_jwt_qal_local test_jwt.cpp  -DREAD_FROM_FILE=1 -I $SGX_SDK/include  -I../ -I../../../../external/jwt-cpp/include -L ../ -lsgx_dcap_qal -lpthread

g++ -g -O0 -o test_jwt_qvl test_jwt.cpp -I $SGX_SDK/include  -I../ -I../../../../external/jwt-cpp/include -L ../../../dcap_quoteverify/linux/ -lsgx_dcap_quoteverify -lpthread
