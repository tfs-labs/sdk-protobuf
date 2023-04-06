#!/bin/sh


echo "-- start make depend:"

SHDIR=$(dirname `readlink -f $0`)
#         build ，  cd    
echo "make_depend.sh execute dir:" $SHDIR

OPENSSL_DIR=./openssl

PROTOBUF_DIR=./protobuf



COMPILE_NUM=`cat /proc/cpuinfo| grep  "processor" | wc -l`;



# openssl
cd $SHDIR
if [ -d ${OPENSSL_DIR} ];
then 
    echo "openssl compile";
else
    tar -xvf ./3rd/openssl-3.0.5.tar.gz;
    mv openssl-3.0.5 openssl;
    cd ${OPENSSL_DIR} && ./Configure && make -j$COMPILE_NUM;
fi;



# protobuf
cd $SHDIR
if [ -d ${PROTOBUF_DIR} ]; 
then 
    echo "protobuf compile";
else
    unzip ./3rd/protobuf-cpp-3.21.9.zip -d ./;
    mv protobuf-3.21.9 protobuf;
    cd ${PROTOBUF_DIR} && ./configure && make -j$COMPILE_NUM;
fi;


cd $1
echo "-- make depend done"




