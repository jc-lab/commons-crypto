import crypto from "crypto";

const chai = require('chai');
const expect = chai.expect;
const assert = chai.assert;
const should = chai.should();

import * as cc from '../src';

const USE_CONSOLE_OUTPUT = process.env.USE_CONSOLE_OUTPUT || false;

describe('RSA Create Key', function () {
  const nodePrivKey = crypto.createPrivateKey(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCz764g9Dr4ZXQDEw8+Il2mbWQ5ACInIBklISsqBmAh5SbnZkqv
cuZ6aj69AHV7IhrDujm730daSH8+wZjHV011V8/sSdK4qvvX0bRql3YUTNQbsBDj
PaV8RRHqHEw/NobbeqtX8QIRvF4eeRyjmLodI1G0N1JinKuM1XYpyKvqlQIDAQAB
AoGAO0CI+acTKCrYag7DrTVJ230YTMDjfjjOrvBeM2eIDoFUL0z6+Q2AIf2MjVZy
WUrgv2U6j8g1yeAnrrW3pqT0B0tQGYYAtAELNe2VZbBBVYQOUS53kq3VowYYMM3z
8R2rEmZTsreFT6uq9+9RMtm5W9ugti//BMte5T8JP5o0l10CQQDntf/ieUmndkGr
t55ROUZZOZJmjr5CTELvjbwnFDx50qh6b1Tzld6l/Gps2b+KxcVswM86Q25PAnbx
VP/rmWoTAkEAxsxMcIcvuDes5A2UcVU7TiyYAsO9vVEfqtDDff50PXd/xNa7ICe0
VtJmVazm8B5K6fVh0Z3EUNff+lRyz61ttwJATmI5D8nr6qSMjqRtABkZ/TEGn38G
SbM2qYcO8UFdO/DRYamr2UMHsKr07aGztCQ3JxUKhTEubbftuLICaRba1QJAfxYL
p8REVVgCRqgHxYvfJdKMOvg3S9eYjvJ2hw0r8j96hrNfXOcE+pv2n76ww8AZ1Aby
Sba50ZSvsrBZ1TnhcQJBAK/jKY+AXaACpoPrradRA80S+WEq8L10o7UYFPxgDdcN
s2QyKSJ2+ZiRXRFpd7L3j6REj+YELpq+10s5lvkgbyU=
-----END RSA PRIVATE KEY-----`);
  const nodePubKey = crypto.createPublicKey(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCz764g9Dr4ZXQDEw8+Il2mbWQ5
ACInIBklISsqBmAh5SbnZkqvcuZ6aj69AHV7IhrDujm730daSH8+wZjHV011V8/s
SdK4qvvX0bRql3YUTNQbsBDjPaV8RRHqHEw/NobbeqtX8QIRvF4eeRyjmLodI1G0
N1JinKuM1XYpyKvqlQIDAQAB
-----END PUBLIC KEY-----`);
  const pubKey = cc.createAsymmetricKeyFromNode(nodePubKey);
  const priKey = cc.createAsymmetricKeyFromNode(nodePrivKey);

  it('PKCS1 PEM Private Key', function () {
    const experimentalKey = cc.createAsymmetricKey({
      key: `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCz764g9Dr4ZXQDEw8+Il2mbWQ5ACInIBklISsqBmAh5SbnZkqv
cuZ6aj69AHV7IhrDujm730daSH8+wZjHV011V8/sSdK4qvvX0bRql3YUTNQbsBDj
PaV8RRHqHEw/NobbeqtX8QIRvF4eeRyjmLodI1G0N1JinKuM1XYpyKvqlQIDAQAB
AoGAO0CI+acTKCrYag7DrTVJ230YTMDjfjjOrvBeM2eIDoFUL0z6+Q2AIf2MjVZy
WUrgv2U6j8g1yeAnrrW3pqT0B0tQGYYAtAELNe2VZbBBVYQOUS53kq3VowYYMM3z
8R2rEmZTsreFT6uq9+9RMtm5W9ugti//BMte5T8JP5o0l10CQQDntf/ieUmndkGr
t55ROUZZOZJmjr5CTELvjbwnFDx50qh6b1Tzld6l/Gps2b+KxcVswM86Q25PAnbx
VP/rmWoTAkEAxsxMcIcvuDes5A2UcVU7TiyYAsO9vVEfqtDDff50PXd/xNa7ICe0
VtJmVazm8B5K6fVh0Z3EUNff+lRyz61ttwJATmI5D8nr6qSMjqRtABkZ/TEGn38G
SbM2qYcO8UFdO/DRYamr2UMHsKr07aGztCQ3JxUKhTEubbftuLICaRba1QJAfxYL
p8REVVgCRqgHxYvfJdKMOvg3S9eYjvJ2hw0r8j96hrNfXOcE+pv2n76ww8AZ1Aby
Sba50ZSvsrBZ1TnhcQJBAK/jKY+AXaACpoPrradRA80S+WEq8L10o7UYFPxgDdcN
s2QyKSJ2+ZiRXRFpd7L3j6REj+YELpq+10s5lvkgbyU=
-----END RSA PRIVATE KEY-----`
    });
    expect(priKey.equals(experimentalKey)).to.equals(true);
  });

  it('PKCS1 DER Private Key', function () {
    const experimentalKey = cc.createAsymmetricKey({
      key: Buffer.from(`MIICXAIBAAKBgQCz764g9Dr4ZXQDEw8+Il2mbWQ5ACInIBklISsqBmAh5SbnZkqv
cuZ6aj69AHV7IhrDujm730daSH8+wZjHV011V8/sSdK4qvvX0bRql3YUTNQbsBDj
PaV8RRHqHEw/NobbeqtX8QIRvF4eeRyjmLodI1G0N1JinKuM1XYpyKvqlQIDAQAB
AoGAO0CI+acTKCrYag7DrTVJ230YTMDjfjjOrvBeM2eIDoFUL0z6+Q2AIf2MjVZy
WUrgv2U6j8g1yeAnrrW3pqT0B0tQGYYAtAELNe2VZbBBVYQOUS53kq3VowYYMM3z
8R2rEmZTsreFT6uq9+9RMtm5W9ugti//BMte5T8JP5o0l10CQQDntf/ieUmndkGr
t55ROUZZOZJmjr5CTELvjbwnFDx50qh6b1Tzld6l/Gps2b+KxcVswM86Q25PAnbx
VP/rmWoTAkEAxsxMcIcvuDes5A2UcVU7TiyYAsO9vVEfqtDDff50PXd/xNa7ICe0
VtJmVazm8B5K6fVh0Z3EUNff+lRyz61ttwJATmI5D8nr6qSMjqRtABkZ/TEGn38G
SbM2qYcO8UFdO/DRYamr2UMHsKr07aGztCQ3JxUKhTEubbftuLICaRba1QJAfxYL
p8REVVgCRqgHxYvfJdKMOvg3S9eYjvJ2hw0r8j96hrNfXOcE+pv2n76ww8AZ1Aby
Sba50ZSvsrBZ1TnhcQJBAK/jKY+AXaACpoPrradRA80S+WEq8L10o7UYFPxgDdcN
s2QyKSJ2+ZiRXRFpd7L3j6REj+YELpq+10s5lvkgbyU=`, 'base64')
    });
    expect(priKey.equals(experimentalKey)).to.equals(true);
  });

  it('PKCS8 PEM Private Key', function () {
    const experimentalKey = cc.createAsymmetricKey({
      key: `-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALPvriD0OvhldAMT
Dz4iXaZtZDkAIicgGSUhKyoGYCHlJudmSq9y5npqPr0AdXsiGsO6ObvfR1pIfz7B
mMdXTXVXz+xJ0riq+9fRtGqXdhRM1BuwEOM9pXxFEeocTD82htt6q1fxAhG8Xh55
HKOYuh0jUbQ3UmKcq4zVdinIq+qVAgMBAAECgYA7QIj5pxMoKthqDsOtNUnbfRhM
wON+OM6u8F4zZ4gOgVQvTPr5DYAh/YyNVnJZSuC/ZTqPyDXJ4CeutbempPQHS1AZ
hgC0AQs17ZVlsEFVhA5RLneSrdWjBhgwzfPxHasSZlOyt4VPq6r371Ey2blb26C2
L/8Ey17lPwk/mjSXXQJBAOe1/+J5Sad2Qau3nlE5Rlk5kmaOvkJMQu+NvCcUPHnS
qHpvVPOV3qX8amzZv4rFxWzAzzpDbk8CdvFU/+uZahMCQQDGzExwhy+4N6zkDZRx
VTtOLJgCw729UR+q0MN9/nQ9d3/E1rsgJ7RW0mZVrObwHkrp9WHRncRQ19/6VHLP
rW23AkBOYjkPyevqpIyOpG0AGRn9MQaffwZJszaphw7xQV078NFhqavZQwewqvTt
obO0JDcnFQqFMS5tt+24sgJpFtrVAkB/FgunxERVWAJGqAfFi98l0ow6+DdL15iO
8naHDSvyP3qGs19c5wT6m/afvrDDwBnUBvJJtrnRlK+ysFnVOeFxAkEAr+Mpj4Bd
oAKmg+utp1EDzRL5YSrwvXSjtRgU/GAN1w2zZDIpInb5mJFdEWl3svePpESP5gQu
mr7XSzmW+SBvJQ==
-----END PRIVATE KEY-----`
    });
    expect(priKey.equals(experimentalKey)).to.equals(true);
  });

  it('PKCS8 DER Private Key', function () {
    const experimentalKey = cc.createAsymmetricKey({
      key: Buffer.from(`MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALPvriD0OvhldAMT
Dz4iXaZtZDkAIicgGSUhKyoGYCHlJudmSq9y5npqPr0AdXsiGsO6ObvfR1pIfz7B
mMdXTXVXz+xJ0riq+9fRtGqXdhRM1BuwEOM9pXxFEeocTD82htt6q1fxAhG8Xh55
HKOYuh0jUbQ3UmKcq4zVdinIq+qVAgMBAAECgYA7QIj5pxMoKthqDsOtNUnbfRhM
wON+OM6u8F4zZ4gOgVQvTPr5DYAh/YyNVnJZSuC/ZTqPyDXJ4CeutbempPQHS1AZ
hgC0AQs17ZVlsEFVhA5RLneSrdWjBhgwzfPxHasSZlOyt4VPq6r371Ey2blb26C2
L/8Ey17lPwk/mjSXXQJBAOe1/+J5Sad2Qau3nlE5Rlk5kmaOvkJMQu+NvCcUPHnS
qHpvVPOV3qX8amzZv4rFxWzAzzpDbk8CdvFU/+uZahMCQQDGzExwhy+4N6zkDZRx
VTtOLJgCw729UR+q0MN9/nQ9d3/E1rsgJ7RW0mZVrObwHkrp9WHRncRQ19/6VHLP
rW23AkBOYjkPyevqpIyOpG0AGRn9MQaffwZJszaphw7xQV078NFhqavZQwewqvTt
obO0JDcnFQqFMS5tt+24sgJpFtrVAkB/FgunxERVWAJGqAfFi98l0ow6+DdL15iO
8naHDSvyP3qGs19c5wT6m/afvrDDwBnUBvJJtrnRlK+ysFnVOeFxAkEAr+Mpj4Bd
oAKmg+utp1EDzRL5YSrwvXSjtRgU/GAN1w2zZDIpInb5mJFdEWl3svePpESP5gQu
mr7XSzmW+SBvJQ==`, 'base64')
    });
    expect(priKey.equals(experimentalKey)).to.equals(true);
  });

  it('PKCS1 PEM Public Key', function () {
    const experimentalKey = cc.createAsymmetricKey({
      key: `-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALPvriD0OvhldAMTDz4iXaZtZDkAIicgGSUhKyoGYCHlJudmSq9y5npq
Pr0AdXsiGsO6ObvfR1pIfz7BmMdXTXVXz+xJ0riq+9fRtGqXdhRM1BuwEOM9pXxF
EeocTD82htt6q1fxAhG8Xh55HKOYuh0jUbQ3UmKcq4zVdinIq+qVAgMBAAE=
-----END RSA PUBLIC KEY-----`
    });
    expect(pubKey.equals(experimentalKey)).to.equals(true);
  });

  it('PKCS1 DER Public Key', function () {
    const experimentalKey = cc.createAsymmetricKey({
      key: Buffer.from(`MIGJAoGBALPvriD0OvhldAMTDz4iXaZtZDkAIicgGSUhKyoGYCHlJudmSq9y5npq
Pr0AdXsiGsO6ObvfR1pIfz7BmMdXTXVXz+xJ0riq+9fRtGqXdhRM1BuwEOM9pXxF
EeocTD82htt6q1fxAhG8Xh55HKOYuh0jUbQ3UmKcq4zVdinIq+qVAgMBAAE=`, 'base64')
    });
    expect(pubKey.equals(experimentalKey)).to.equals(true);
  });

  it('SPKI PEM Public Key', function () {
    const experimentalKey = cc.createAsymmetricKey({
      key: `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCz764g9Dr4ZXQDEw8+Il2mbWQ5
ACInIBklISsqBmAh5SbnZkqvcuZ6aj69AHV7IhrDujm730daSH8+wZjHV011V8/s
SdK4qvvX0bRql3YUTNQbsBDjPaV8RRHqHEw/NobbeqtX8QIRvF4eeRyjmLodI1G0
N1JinKuM1XYpyKvqlQIDAQAB
-----END PUBLIC KEY-----`
    });
    expect(pubKey.equals(experimentalKey)).to.equals(true);
  });

  it('SPKI DER Public Key', function () {
    const experimentalKey = cc.createAsymmetricKey({
      key: Buffer.from(`MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCz764g9Dr4ZXQDEw8+Il2mbWQ5
ACInIBklISsqBmAh5SbnZkqvcuZ6aj69AHV7IhrDujm730daSH8+wZjHV011V8/s
SdK4qvvX0bRql3YUTNQbsBDjPaV8RRHqHEw/NobbeqtX8QIRvF4eeRyjmLodI1G0
N1JinKuM1XYpyKvqlQIDAQAB`, 'base64')
    });
    expect(pubKey.equals(experimentalKey)).to.equals(true);
  });
});
