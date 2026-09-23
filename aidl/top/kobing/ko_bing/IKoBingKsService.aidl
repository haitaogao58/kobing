package top.kobing.ko_bing;

import android.hardware.security.keymint.SecurityLevel;
import android.hardware.security.keymint.Certificate;
import android.hardware.security.keymint.Tag;
import android.system.keystore2.Domain;
import android.system.keystore2.IKeystoreSecurityLevel;
import android.system.keystore2.KeyDescriptor;
import android.system.keystore2.KeyEntryResponse;

import top.kobing.ko_bing.IKoBingSecurityLevel;
import top.kobing.ko_bing.CallerInfo;

interface IKoBingKsService {

    IKeystoreSecurityLevel getSecurityLevel(in SecurityLevel securityLevel);

    IKoBingSecurityLevel getKoBingSecurityLevel(in SecurityLevel securityLevel);

    KeyEntryResponse getKeyEntry(in @nullable CallerInfo ctx, in KeyDescriptor key);


    void updateSubcomponent(in @nullable CallerInfo ctx, in KeyDescriptor key,
                            in @nullable byte[] publicCert, in @nullable byte[] certificateChain);


    KeyDescriptor[] listEntries(in @nullable CallerInfo ctx, in Domain domain, in long nspace);


    void deleteKey(in @nullable CallerInfo ctx, in KeyDescriptor key);


    KeyDescriptor grant(in @nullable CallerInfo ctx, in KeyDescriptor key, in int granteeUid, in int accessVector);


    void ungrant(in @nullable CallerInfo ctx, in KeyDescriptor key, in int granteeUid);


    int getNumberOfEntries(in @nullable CallerInfo ctx, in Domain domain, in long nspace);


    KeyDescriptor[] listEntriesBatched(in @nullable CallerInfo ctx, in Domain domain, in long nspace,
            in @nullable String startingPastAlias);

    byte[] getSupplementaryAttestationInfo(in Tag tag);

    void updateEcKeybox(in @nullable CallerInfo ctx, in byte[] key, in List<Certificate> chain);

    void updateRsaKeybox(in @nullable CallerInfo ctx, in byte[] key, in List<Certificate> chain);

    boolean isKoBingGrant(in @nullable CallerInfo ctx, in KeyDescriptor grant);
}
