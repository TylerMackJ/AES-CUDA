all : bin/main

bin/main : src/main.cu bin/
	nvcc src/main.cu -o bin/main

bin/ :
	mkdir bin/

clean : bin/
	rm -r bin/