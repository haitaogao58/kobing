package top.kobing.ko_bing;

import android.hardware.security.keymint.HardwareAuthToken;
import android.hardware.security.keymint.HardwareAuthenticatorType;
import android.security.authorization.AuthorizationTokens;
import top.kobing.ko_bing.CallerInfo;

interface IKoBingAuthorizationService {
    void addAuthToken(in @nullable CallerInfo ctx, in HardwareAuthToken authToken);

    void onDeviceUnlocked(in @nullable CallerInfo ctx, in int userId, in @nullable byte[] password);

    void onDeviceLocked(in @nullable CallerInfo ctx, in int userId, in long[] unlockingSids,
            in boolean weakUnlockEnabled);

    void onUserStorageLocked(in @nullable CallerInfo ctx, in int userId);

    void onWeakUnlockMethodsExpired(in @nullable CallerInfo ctx, in int userId);

    void onNonLskfUnlockMethodsExpired(in @nullable CallerInfo ctx, in int userId);

    AuthorizationTokens getAuthTokensForCredStore(in @nullable CallerInfo ctx, in long challenge,
            in long secureUserId, in long authTokenMaxAgeMillis);

    long getLastAuthTime(in @nullable CallerInfo ctx, in long secureUserId,
            in HardwareAuthenticatorType[] authTypes);
}
