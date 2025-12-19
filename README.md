Don't forget to use `wasm32-wasip1`:

```bash
rustup target add wasm32-wasip1
```

And compile with : 

```bash
cargo build --release --target wasm32-wasip1
```

The WASM file will appear in : `target/wasm32-wasip1/release/edge_waf.wasm
`