FROM ubuntu:focal

WORKDIR /workdir
COPY . /workdir/symsan
RUN apt-get update
RUN apt-get install -y cmake llvm-12 clang-12 libc++-12-dev libc++abi-12-dev python zlib1g-dev
RUN cd symsan/ && mkdir -p build && \
    cd build && CC=clang-12 CXX=clang++-12 cmake -DCMAKE_INSTALL_PREFIX=. ../  && \
    make -j && make install
RUN apt-get install -y libprotobuf-dev protobuf-compiler libunwind-dev vim git curl
#install cargo
RUN if ! [ -x "$(command -v rustc)" ]; then curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y; fi
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cd symsan && cargo build --release && cp target/release/libruntime_fast.a build/lib/symsan && ./run.sh



