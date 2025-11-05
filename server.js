import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";

const app = express();
app.use(bodyParser.json({ limit: "1mb" }));

// RSA秘密鍵（Pythonとペア）
const PRIVATE_KEY = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAoDwF1nDlZvU0+AcPy25Wmqvb1dCElFPajsxxec78EEygtzoN
TB1WzACLw9lA1l8FYAUvIklToDOqK4jKrvveX2LLvOdUUZPQpCxA9muxamKdHyaS
PT4sytQuft4J0dIMwWI7r9WoP/yaTLzHNTNHwKRMiFPiIts8q4cKJ4o1eZS0Z4Ov
abJXPFPED6rjO2mhJIxrmlVqhmFTknWnxukQR5l71AOYGILnSyDbjjp2ZVEBxNHi
g9MLsAJFhMSI4z16NQPGkHMDXDWINToTmfg5Bk+CV9rrz9QtIdGIHR3tf5rsofJX
PpgPjm4GwTBRPHZU0aw7voeISfppq4BjnDrjHwIDAQABAoIBACbTZHa5lFyGPfd7
fpBEhCemTPZaOEXYq7S+RSDGzr0EVE0Re/ddhJKZ70PdeKB5FcxWdT1RlznSSwGR
e8s6rH9gaQ203/GEZ6HgNz1+itbEXl4V8ol0b1YWY83J74cv5ndVXjEVDFe01Y6S
j5KMgm5jYUgHS1w201ScvBEopBx5UUITKoT65O3F6iC7Cv8IVuUx44pjJEuyT9CI
dUSD9KlIKWbxGFI7NLEhUxlt7xLn2Jr4a896Pr5ZN8ljgomjQtTzzaSbwCXU2dpt
u5BtFOkNmxtGmhKlSpdP7p7Mc/9NpjQM0ipQiu7vQHkjmvJke5aE7TGCxOKOPvVa
dJ7UAoECgYEA3v5Oia/6oraD/yii1f8Tc0KjIMqL1SV6b2Fd6Nvi9ncLfhN7vrgp
ijKyS0skXxPaUUIcPJXi4KkiTWV8nprK1OW4p4eB8RuG51bGXJVXeXTOwq+pMdNh
gUfyzYUj2ZOrt4jpCvEyawOMFIibysVcR3PHITf4Uj7BbgU7r7FxjFcCgYEAt/Ol
qWYPPj+8jfv4QfMojufUxksZ84sYvr7SyKOvana3N6w+F3wmLlbiTtTNeXLiMQun
/04t19VaIZuNXX8qWh5O0cbjUvf+NM5WeMGu+kdOYmZDshlYyx2qh80P1AWziSg0
qOotdRdK72CfjPIlTg9YeC5Yrw7pg8fn8Yr0InkCgYEA1OJnTB9K4afo3+GFg1Le
2LyXS6jSUgxTlJ2Zr8KsLKt9t0EWc/8Q+TRo7mSwNmyXkdfRaS2WyO/vJYBrtmcE
mLcu0BEXxnyHD7fR63VPa05OTaKxnjW08l0juX0Pupm156O3B5E4lt1uD/RS9wPv
ku8+/cGXOb1boJMyZgq64kUCgYA0NcI6P05qQ5rXzcFbrpE/Zkt88InwFvWyBeU7
r0G1fPZppciFz+XiVySqbTnYk6PhecZ37w+R5+tKCKVp+RLjOyDx53pT7TFIeZwP
cCGixaRYx1/FZ+5M0CG7o5cvfWLEthWkL7sxNag+IvWGAqBV9IMOsVDYduoOTinl
46OBOQKBgQDPM2qc4GBGxYE37HecDpcziK5ueXVCO/FpgF/zX9+lEzdp42AqzsWv
nir6QCw8N3LXTzIpFjfq8o1/KCibaiSpRXQHDd19Ir72IPIdHgFgjxToF0wX4tKw
FSNCY3ul6Hpw422TETdXDdYTstJm07+zFQMQMOpo1GiQ6E9PkTSr5A==
-----END RSA PRIVATE KEY-----
`;

// POST /decrypt
app.post("/decrypt", (req, res) => {
  try {
    const { encrypted_key, iv, ciphertext } = req.body;

    const aesKey = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      },
      Buffer.from(encrypted_key, "base64")
    );

    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      aesKey,
      Buffer.from(iv, "base64")
    );

    let decrypted = decipher.update(Buffer.from(ciphertext, "base64"));
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    const json = JSON.parse(decrypted.toString());
    console.log("✅ 復号結果:", json);

    res.json({ ok: true, data: json });
  } catch (err) {
    console.error("❌ 復号エラー:", err);
    res.status(400).json({ error: err.message });
  }
});

app.listen(8000, () => console.log("🚀 Server running on http://localhost:8000"));
