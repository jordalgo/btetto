fn main() {
    protobuf_codegen::Codegen::new()
        .pure()
        .cargo_out_dir("protos_gen/")
        .input("src/protos/perfetto_bpftrace.proto")
        .include("src/protos")
        .run_from_script();
}