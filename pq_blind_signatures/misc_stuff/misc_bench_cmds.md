# ONLY for debugging random stuff!


RUST_MIN_STACK=4194304 cargo test test_sign_loop_conservative_rain -- --nocapture

cargo test test_name --no-run
export LD_LIBRARY_PATH=../mayo-c-rain-sys/target/debug:../vole-rainhash-then-mayo-sys/target/debug:$LD_LIBRARY_PATH
export RUST_MIN_STACK=8194304
gdb file_name

cargo test test_name --nocapture


test_sign_loop_conservative_rain



cargo test test_sign_loop_conservative_rain -- --nocapture

cargo test test_sign_loop_conservative_rain --no-run

valgrind --max-stackframe=2129008 --leak-check=full --track-origins=yes target/debug/deps/blind_signatures_conservative_rain-a8f98ba4fbb01047


-------------------------------------------------------------------------------------------------------------------------------------------------------------------------

cargo clean

cargo test test_sign_loop_optimized --no-run

export LD_LIBRARY_PATH=../mayo-c-sys/target/debug:../vole-mayo-sys/target/debug:$LD_LIBRARY_PATH

RUST_MIN_STACK=4194304 cargo test test_sign_loop_optimized --no-run

RUST_MIN_STACK=4194304 cargo test test_sign_loop_optimized -- --nocapture

gdb target/debug/deps/blind_signatures-cfbf919ebe259eea

valgrind --max-stackframe=2129008 --leak-check=full --track-origins=yes target/debug/deps/blind_signatures-cfbf919ebe259eea

