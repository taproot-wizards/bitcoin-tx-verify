test:
    cargo test

clean:
    cd depends/bitcoin && make clean && cd ../.. && cargo clean
