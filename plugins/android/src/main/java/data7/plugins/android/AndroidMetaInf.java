package data7.plugins.android;

import data7.project.MetaInformation;

import java.util.HashMap;
import java.util.Map;

public class AndroidMetaInf {
    public static final String ANDROID_NVD = "android";


    public static final Map<String, MetaInformation> getAndroid() {
        String[] repo = new String[]{
                "platform/frameworks/opt/net/wifi",
                "platform/frameworks/base",
                "platform/external/libavc",
                "platform/frameworks/native",
                "platform/frameworks/av",
                "platform/external/libhevc",
                "kernel/arm64",
                "kernel/bcm",
                "kernel/build",
                "kernel/common",
                "kernel/configs",
                "kernel/exynos",
                "kernel/goldfish",
                "kernel/hikey-linaro",
                "kernel/lk",
                "kernel/manifest",
                "kernel/mediatek",
                "kernel/msm",
                "kernel/omap",
                "kernel/samsung",
                "kernel/tegra",
                "kernel/tests",
                "kernel/x86",
                "kernel/x86_64",
                /*
                platform/external/bouncycastle ,
                platform/external/libnl ,
                platform/packages/services/Telephony ,
                platform/external/libmpeg2 ,
                platform/external/flac ,
                platform/packages/apps/Settings ,
                platform/external/wpa_supplicant_8 ,
                platform/hardware/qcom/display ,
                platform/hardware/qcom/audio ,
                platform/manifest ,
                platform/frameworks/minikin ,
                platform/libcore ,
                platform/external/tremolo ,
                platform/external/libvpx ,
                platform/external/freetype ,
                platform/external/pdfium ,
                platform/external/libopus ,
                platform/frameworks/ex ,
                platform/packages/apps/ContactsCommon ,
                platform/external/c-ares ,
                platform/system/core ,
                platform/external/sqlite ,
                platform/bootable/recovery ,
                platform/external/aac ,
                platform/external/expat ,
                platform/external/boringssl ,
                platform/hardware/libhardware ,
                platform/packages/apps/Bluetooth ,
                platform/external/sepolicy ,
                platform/system/netd ,
                platform/external/conscrypt ,
                platform/external/libpng ,
                platform/packages/apps/UnifiedEmail ,
                platform/dalvik ,
                platform/packages/apps/CertInstaller
                platform/packages/services/Telecomm ,
                platform/hardware/qcom/sdm845/gps ,
                device/google/marlin ,
                platform/packages/apps/Exchange ,
                platform/hardware/qcom/media ,
                platform/system/update_engine ,
                platform/system/nfc ,
                platform/system/vold ,
                platform/external/v4l2_codec2 ,
                platform/external/f2fs-tools ,
                platform/packages/apps/Stk ,
                device/google/dragon ,
                platform/external/giflib ,
                platform/packages/apps/PackageInstaller ,
                platform/hardware/interfaces ,
                platform/packages/apps/Email ,
                platform/external/dnsmasq ,
                platform/hardware/broadcom/wlan ,
                platform/bionic ,
                platform/system/sepolicy ,
                platform/packages/providers/DownloadProvider ,
                platform/packages/providers/MediaProvider ,
                platform/external/libgdx ,
                platform/hardware/ril ,
                platform/external/dhcpcd ,
                platform/cts ,
                platform/packages/providers/TelephonyProvider ,
                platform/system/security ,
                platform/system/media ,
                platform/external/bluetooth/bluedroid ,
                platform/external/dng_sdk ,
                platform/external/libnfc-nci ,
                platform/external/e2fsprogs ,
                platform/external/jhead ,
                platform/system/libhidl ,
                platform/system/tools/hidl ,
                platform/system/hwservicemanager ,
                platform/external/neven ,
                platform/external/v8 ,
                platform/external/chromium-libpac ,
                platform/external/sfntly ,
                platform/packages/apps/Launcher3 ,
                platform/external/libxaac ,
                platform/external/svox ,


                 */
        }; //Todo to complete

        Map<String,MetaInformation> projects = new HashMap<>();
        for (String aRepo : repo) {
            projects.put(aRepo, new MetaInformation(
                    "https://android.googlesource.com/" + aRepo,
                    ".*?(android\\.googlesource\\.com/" + aRepo + ").*?(\\+/)([a-f0-9]+)",
                    3,
                    ".*?[Bb]ug[ a-zA-Z]*:[ ]*([0-9]+)",
                    1,
                    "https://issuetracker.google.com/",
                    ".*(issuetracker\\.google\\.com).*?(issues\\/)([0-9]+)",
                    3
            ));
        }
        return projects;

    }

}
