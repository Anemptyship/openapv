#!/bin/bash
TAG=$1
OUTPUT_FILE="result_${TAG}.txt"

echo "=== Running Benchmark for $TAG (100 runs) ==="
rm -f $OUTPUT_FILE

for i in {1..100}
do
   # Extact milliseconds value. Output format: "Total decoding time               = 63 msec, 0.063 sec"
   # awk $5 is 63
   ./bin/oapv_app_dec -i ../test/bitstream/qp_C.apv -o /tmp/out.yuv 2>&1 | grep "Total decoding time" | awk '{print $5}' >> $OUTPUT_FILE
   # Simple progress bar
   echo -n "."
   if (( i % 20 == 0 )); then echo ""; fi
done

echo ""
echo "=== Results for $TAG ==="
awk '{ total += $1; min = ($1 < min || min == "") ? $1 : min; max = ($1 > max) ? $1 : max; count++ } END { print "Average:", total/count, "ms"; print "Min:", min, "ms"; print "Max:", max, "ms" }' $OUTPUT_FILE
