FROM ubuntu:latest as base

COPY ./chall_1.S /chall.S

# Install the items necessary to run it.
RUN apt-get update && apt-get install -y \
    binutils-aarch64-linux-gnu \
    qemu-user-static \
    gcc-aarch64-linux-gnu

# Compile the challenge.
RUN aarch64-linux-gnu-gcc -static chall.S -o chall

# Run the challenge.
RUN ./chall 85 6 3 | echo