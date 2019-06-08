#!/bin/bash

export DSOS_CONFIG=/home/rob/dsosd-8.json

C=/opt/rob/SOS/bin/dsos_cmd
CONT=/tmp/tst-cont-$$.sos

fail() {
	echo failed in line ${BASH_LINENO[0]}
	[ "$*" ] && echo $*
	exit 1
}

$C cont --delete $CONT
$C cont --create $CONT 755 ROOT || fail failed to create container

SCHEMA='*seq:uint64,*int1:uint64,data:char[9000]'
$C schema --cont $CONT --schema test1 --add --template $SCHEMA || fail failed to add schema
OUT=`$C schema --cont $CONT --schema test1 --dump`
[ "$SCHEMA" = "$OUT" ] || fail fetched schema differs from saved

cat >csv <<EOF
0,123,bo was here 123
2,125,bo was here 125
1,124,bo was here 124
3,126,bo was here 126
EOF
$C import --cont $CONT --schema test1 csv || fail failed to import csv data

$C iter --cont $CONT --schema test1 --attr seq >iter-out
sort -t, --key=1 csv >csv-sorted
$C iter --cont $CONT --schema test1 --attr int1 >iter-out
sort -t, --key=2 csv >csv-sorted
diff csv-sorted iter-out
rm -f csv

VAL=`$C find --cont $CONT --schema test1 seq=0`
[ "$VAL" = "0,123,bo was here 123" ] || fail finding seq=0
VAL=`$C find --cont $CONT --schema test1 seq=1`
[ "$VAL" = "1,124,bo was here 124" ] || fail finding seq=1
VAL=`$C find --cont $CONT --schema test1 seq=2`
[ "$VAL" = "2,125,bo was here 125" ] || fail finding seq=2
VAL=`$C find --cont $CONT --schema test1 seq=3`
[ "$VAL" = "3,126,bo was here 126" ] || fail finding seq=3

VAL=`$C find --cont $CONT --schema test1 int1=123`
[ "$VAL" = "0,123,bo was here 123" ] || fail finding int1=123
VAL=`$C find --cont $CONT --schema test1 int1=124`
[ "$VAL" = "1,124,bo was here 124" ] || fail finding int1=124
VAL=`$C find --cont $CONT --schema test1 int1=125`
[ "$VAL" = "2,125,bo was here 125" ] || fail finding int1=125
VAL=`$C find --cont $CONT --schema test1 int1=126`
[ "$VAL" = "3,126,bo was here 126" ] || fail finding int1=126

$C cont --delete $CONT
