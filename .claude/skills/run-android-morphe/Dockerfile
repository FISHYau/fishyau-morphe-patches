# Public-base Android/JDK build environment. No private parent image required.
# Build only after the human accepts the license corresponding to the supplied hash.
FROM eclipse-temurin:21.0.13_9-jdk-jammy
ARG ANDROID_LICENSE_SHA1
ARG TOOLS_URL=https://dl.google.com/android/repository/commandlinetools-linux-16111833_latest.zip
ARG TOOLS_SHA1=e025545c62a8e64c7559119566a569fb1dec5f60
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip git && rm -rf /var/lib/apt/lists/*
ENV ANDROID_HOME=/opt/android-sdk
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV GRADLE_USER_HOME=/gradle-home
ENV PATH=/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/platform-tools:/opt/java/openjdk/bin:${PATH}
RUN test -n "$ANDROID_LICENSE_SHA1" && mkdir -p /opt/android-sdk/licenses /opt/android-sdk/cmdline-tools /tmp/android-download && \
    printf '%s\n' "$ANDROID_LICENSE_SHA1" > /opt/android-sdk/licenses/android-sdk-license && \
    curl --fail --location --retry 2 "$TOOLS_URL" -o /tmp/android-download/tools.zip && \
    printf '%s  %s\n' "$TOOLS_SHA1" /tmp/android-download/tools.zip | sha1sum -c - && \
    unzip -q /tmp/android-download/tools.zip -d /tmp/android-download/extracted && \
    mv /tmp/android-download/extracted/cmdline-tools /opt/android-sdk/cmdline-tools/latest && \
    rm -rf /tmp/android-download
RUN sdkmanager --sdk_root=/opt/android-sdk 'platforms;android-36' 'build-tools;36.0.0'
WORKDIR /workspace
ENTRYPOINT []
CMD ["/bin/bash"]
