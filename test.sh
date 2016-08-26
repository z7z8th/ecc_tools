#!/bin/bash

TEST_CNT=100
SIGN_CNT=20
KEYSIZE=48
mkdir -p test
cd test

function test_keygen() {
	echo "test_keygen"	
	for ((i=0;i<$TEST_CNT;i++)); do
		../ecc_tools keygen test-pub-$i test-priv-$i;
		[ $? -ne 0 ] && echo "[$i]: test keygen failed"
	done
	chmod 0400 test-pub-* test-priv-*
}

function test_hashgen() {
	echo "test_hashgen"	
	for ((i=0;i<$TEST_CNT;i++)); do
		dd if=/dev/urandom of=test-hash-$i bs=1 count=$KEYSIZE status=none
	done
	chmod 0400 test-hash-*
}

function test_sign() {
	echo "test_sign"
	for ((i=0;i<$TEST_CNT;i++)); do
		for ((j=0;j<$SIGN_CNT;j++)); do
			sign_log=`../ecc_tools sign test-pub-$i test-priv-$i test-hash-$j test-sig-$i-$j`
			[ $? -ne 0 ] && echo "sign [$i-$j] failed."
			echo $sign_log | grep 'this is not an error, ignored'
		done
	done
	chmod 0400 test-sig-*
}

function test_verify() {
	echo "test_verify"
	for ((i=0;i<$TEST_CNT;i++)); do
		for ((j=0;j<$SIGN_CNT;j++)); do
			../ecc_tools verify test-pub-$i test-hash-$j test-sig-$i-$j
			ret=$?
			[ $ret -ne 0 ] && echo "verify [$i-$j] failed $ret."
		done
	done
}

function test_cleanup() {
	rm -f test-pub-*;
	rm -f test-priv-*;
	rm -f test-hash-*;
	rm -f test-sig-*;
}


test_cleanup
test_keygen
test_hashgen
test_sign
test_verify
#test_cleanup


