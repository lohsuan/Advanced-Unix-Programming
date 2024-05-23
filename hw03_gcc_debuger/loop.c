int main() {
    long a = 0;
    for (int i = 0; i < 3; i++) {
        a += 4096;
        printf("%ld\n", a);
    }
    return 0;
}

// printf call at 0x44f115 (breakpoint set here to test restore functionality)