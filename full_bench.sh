#!/bin/bash
TAG=$1
OUTPUT_RESULT="summary_${TAG}.txt"
TEMP_YUV="/tmp/temp_bench_${TAG}.yuv"

# Compile first to be sure
# cd build && make -j8 > /dev/null

FILES=(../test/bitstream/*.apv)
echo "=== Benchmarking ${#FILES[@]} files for $TAG (20 runs each) ==="
printf "%-25s %-10s %-10s %-10s\n" "File" "Avg(ms)" "Min(ms)" "Max(ms)" > $OUTPUT_RESULT

for f in "${FILES[@]}"
do
    filename=$(basename "$f")
    temp_log="temp_${TAG}_${filename}.log"
    rm -f "$temp_log"
    
    echo -n "Running $filename "
    for i in {1..20}
    do
        ./bin/oapv_app_dec -i "$f" -o "$TEMP_YUV" 2>&1 | grep "Total decoding time" | awk '{print $5}' >> "$temp_log"
        echo -n "."
    done
    
    # Calculate stats
    awk -v fname="$filename" '{ sum += $1; if(min==""){min=$1; max=$1}; if($1<min)min=$1; if($1>max)max=$1 } END { printf "%-25s %-10.2f %-10d %-10d\n", fname, sum/NR, min, max }' "$temp_log" >> $OUTPUT_RESULT
    
    echo "" 
    # Show the result for this file immediately
    tail -n 1 $OUTPUT_RESULT
    rm -f "$temp_log"
done

rm -f "$TEMP_YUV"
echo "=== Final Summary for $TAG ==="
cat $OUTPUT_RESULT
