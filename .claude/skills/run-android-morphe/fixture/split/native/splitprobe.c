#include <jni.h>

#if defined(__aarch64__)
#define FIXTURE_ABI "arm64-v8a"
#elif defined(__x86_64__)
#define FIXTURE_ABI "x86_64"
#else
#error Unsupported split fixture ABI
#endif

/* No synthetic ELF bytes: compile with the explicit NDK r27d Clang target. */
JNIEXPORT jstring JNICALL
Java_dev_morphe_splitfixture_MainActivity_nativeValue(JNIEnv *env, jclass type) {
    (void)type;
    return (*env)->NewStringUTF(env, "JNI_OK_" FIXTURE_ABI);
}
