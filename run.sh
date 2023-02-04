cd build
make -j && make install
cd ..
KO_CC=clang-12 USE_TRACK=1 KO_USE_FASTGEN=1 ./build/bin/ko-clang tests/mini.c -o mini.track
KO_CC=clang-12 ./build/bin/ko-clang tests/mini.c -o  mini.fast
