package com.tamoda.security;

import com.google.appinventor.components.annotations.*;
import com.google.appinventor.components.common.ComponentCategory;
import com.google.appinventor.components.runtime.*;

import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import android.os.Build;
import java.io.File;
import java.security.MessageDigest;

@DesignerComponent(
    version = 1,
    description = "Tamoda Security Elite. Senjata Anti-Tuyul: Deteksi Emulator, Root, Mod, dan Verifikasi Signature APK.",
    category = ComponentCategory.EXTENSION,
    nonVisible = true,
    iconName = ""
)
@SimpleObject(external = true)
public class TamodaSecurity extends AndroidNonvisibleComponent {
    
    private Context context;

    public TamodaSecurity(ComponentContainer container) {
        super(container.$form());
        this.context = container.$context();
    }

    // 1. DETEKSI EMULATOR (Nox, Bluestacks, LDPlayer, dll)
    @SimpleFunction(description = "Mengembalikan nilai true jika user menggunakan Emulator.")
    public boolean IsEmulator() {
        return (Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.MANUFACTURER.contains("Genymotion")
                || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
                || "google_sdk".equals(Build.PRODUCT));
    }

    // 2. DETEKSI ROOT & MAGISK
    @SimpleFunction(description = "Mengembalikan nilai true jika HP user di-Root.")
    public boolean IsRooted() {
        String buildTags = Build.TAGS;
        if (buildTags != null && buildTags.contains("test-keys")) {
            return true;
        }
        String[] paths = {
            "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", 
            "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su", 
            "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su"
        };
        for (String path : paths) {
            if (new File(path).exists()) return true;
        }
        return false;
    }

    // 3. ANTI CLONE (Kunci Package Name)
    @SimpleFunction(description = "Mengembalikan true jika Package Name sesuai dengan aslinya (Anti-Clone/Dual Space).")
    public boolean IsPackageNameValid(String expectedPackageName) {
        return context.getPackageName().equals(expectedPackageName);
    }

    // 4. DETEKSI INSTALASI DARI PLAY STORE
    @SimpleFunction(description = "Mengembalikan true jika aplikasi resmi didownload dari Google Play Store.")
    public boolean IsInstalledFromPlayStore() {
        try {
            String installer = context.getPackageManager().getInstallerPackageName(context.getPackageName());
            // Jika null, berarti diinstal dari File Manager/Browser. Jika vending, berarti Play Store.
            return installer != null && installer.equals("com.android.vending");
        } catch (Exception e) {
            return false;
        }
    }

    // 5. DAPATKAN HASH SIGNATURE (Untuk mencari tahu kode asli APK bos)
    @SimpleFunction(description = "Mendapatkan kode Hash SHA-256 asli dari APK yang sedang berjalan.")
    public String GetAppSignatureHash() {
        try {
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
            for (Signature signature : packageInfo.signatures) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(signature.toByteArray());
                byte[] digest = md.digest();
                StringBuilder hexString = new StringBuilder();
                for (byte b : digest) {
                    String hex = Integer.toHexString(0xff & b);
                    if (hex.length() == 1) hexString.append('0');
                    hexString.append(hex);
                }
                return hexString.toString();
            }
        } catch (Exception e) {
            return "ERROR";
        }
        return "UNKNOWN";
    }

    // 6. ANTI MOD (Validasi Dual Signature: APK & Play Store)
    @SimpleFunction(description = "Mengembalikan true jika Hash Signature cocok dengan APK asli ATAU Play Store. Aman dan anti ribet.")
    public boolean IsSignatureValidDual(String hashApk, String hashPlayStore) {
        String currentHash = GetAppSignatureHash();
        return currentHash.equalsIgnoreCase(hashApk) || currentHash.equalsIgnoreCase(hashPlayStore);
    }

    // 7. ANTI MOD VERSI LAMA (Validasi Signature Tunggal)
    @SimpleFunction(description = "Mengembalikan true jika Hash Signature APK cocok dengan Hash tunggal.")
    public boolean IsSignatureValid(String originalHash) {
        String currentHash = GetAppSignatureHash();
        return currentHash.equalsIgnoreCase(originalHash);
    }
}
