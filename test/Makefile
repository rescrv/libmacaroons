fuzz-testing:
	rm -rf fuzz-testing
	mkdir -p fuzz-testing fuzz-testing/testcases-pre fuzz-testing/testcases fuzz-testing/out
	cmake -DCMAKE_C_COMPILER=afl-clang -B fuzz-testing/build -S ..
	make -C fuzz-testing/build fuzz_serializer -j6
	find unit -type f -name "serialization*" -not -name "*.sh" | xargs -I{} cp "{}" fuzz-testing/testcases-pre
	afl-cmin -i fuzz-testing/testcases-pre -o fuzz-testing/testcases -- fuzz-testing/build/fuzz_serializer
	@echo "Execute: afl-fuzz -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/build/fuzz_serializer"

fuzzing-start:
	afl-fuzz -S fuzzer1 -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/build/fuzz_serializer > /dev/null &
	afl-fuzz -S fuzzer2 -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/build/fuzz_serializer > /dev/null &
	afl-fuzz -S fuzzer3 -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/build/fuzz_serializer > /dev/null &
	afl-fuzz -S fuzzer4 -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/build/fuzz_serializer > /dev/null &
	afl-fuzz -S fuzzer5 -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/build/fuzz_serializer > /dev/null &
	afl-fuzz -S fuzzer6 -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/build/fuzz_serializer > /dev/null &
	afl-fuzz -S fuzzer7 -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/build/fuzz_serializer > /dev/null &
	afl-fuzz -M fuzzer0 -i fuzz-testing/testcases -o fuzz-testing/out fuzz-testing/build/fuzz_serializer

fuzzing-stop:
	-killall fuzzer
	-killall afl-fuzz


.PHONY: fuzz-testing fuzzing-start fuzzing-stop
