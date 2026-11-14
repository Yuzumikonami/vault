package com.xnlr.vault

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.activity.compose.setContent
import androidx.compose.ui.Alignment
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.lifecycle.lifecycleScope
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.runtime.Composable
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.*
import java.security.*
import javax.crypto.*
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import java.io.StringWriter
import java.io.StringReader
import java.security.SecureRandom

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            CryptoApp()
        }
    }
}

/** ---------- RSA 密钥生成 ---------- **/

fun generateRSAKeyPair(): KeyPair {
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(2048)
    return kpg.generateKeyPair()
}

fun publicKeyToPem(publicKey: PublicKey): String {
    StringWriter().use { writer ->
        JcaPEMWriter(writer).use { pemWriter ->
            pemWriter.writeObject(publicKey)
        }
        return writer.toString()
    }
}

fun privateKeyToPem(privateKey: PrivateKey): String {
    StringWriter().use { writer ->
        JcaPEMWriter(writer).use { pemWriter ->
            pemWriter.writeObject(privateKey)
        }
        return writer.toString()
    }
}

fun pemToPublicKey(pemString: String): PublicKey? {
    return try {
        StringReader(pemString.trim()).use { reader ->
            PEMParser(reader).use { parser ->
                val converter = JcaPEMKeyConverter()
                val obj = parser.readObject()
                when (obj) {
                    is SubjectPublicKeyInfo -> converter.getPublicKey(obj)
                    is PublicKey -> obj
                    else -> null
                }
            }
        }
    } catch (e: Exception) {
        Log.e("PEM", "解析公钥失败: ${e.message}")
        null
    }
}

fun pemToPrivateKey(pemString: String): PrivateKey? {
    return try {
        StringReader(pemString.trim()).use { reader ->
            PEMParser(reader).use { parser ->
                val converter = JcaPEMKeyConverter()
                val obj = parser.readObject()
                when (obj) {
                    is PrivateKeyInfo -> converter.getPrivateKey(obj)
                    is PrivateKey -> obj
                    is org.bouncycastle.openssl.PEMKeyPair -> {
                        // 处理 PKCS#1 格式的 RSA 私钥
                        converter.getPrivateKey(obj.privateKeyInfo)
                    }
                    else -> {
                        Log.e("PEM", "未知的私钥格式: ${obj?.javaClass?.name}")
                        null
                    }
                }
            }
        }
    } catch (e: Exception) {
        Log.e("PEM", "解析私钥失败: ${e.message}")
        e.printStackTrace()
        null
    }
}

/** ---------- AES/GCM ---------- **/

fun generateAESKey(): SecretKey {
    val kg = KeyGenerator.getInstance("AES")
    kg.init(256)
    return kg.generateKey()
}

suspend fun encryptFile(
    context: Context,
    inputUri: Uri,
    outputUri: Uri,
    aesKey: SecretKey
): ByteArray = withContext(Dispatchers.IO) {
    val iv = ByteArray(12)
    SecureRandom().nextBytes(iv)

    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val parameterSpec = GCMParameterSpec(128, iv)
    cipher.init(Cipher.ENCRYPT_MODE, aesKey, parameterSpec)

    context.contentResolver.openInputStream(inputUri)?.use { input ->
        context.contentResolver.openOutputStream(outputUri)?.use { output ->
            // 先写入IV (12字节)
            output.write(iv)

            // 然后写入加密数据
            val buffer = ByteArray(8192)
            var bytesRead: Int
            CipherOutputStream(output, cipher).use { cos ->
                while (input.read(buffer).also { bytesRead = it } != -1) {
                    cos.write(buffer, 0, bytesRead)
                }
            }
        }
    }
    iv
}

suspend fun decryptFile(
    context: Context,
    inputUri: Uri,
    outputUri: Uri,
    aesKey: SecretKey
) = withContext(Dispatchers.IO) {
    context.contentResolver.openInputStream(inputUri)?.use { input ->
        // 读取IV (前12字节)
        val iv = ByteArray(12)
        if (input.read(iv) != 12) {
            throw IOException("Invalid encrypted file format: IV missing")
        }

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val parameterSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, aesKey, parameterSpec)

        context.contentResolver.openOutputStream(outputUri)?.use { output ->
            val buffer = ByteArray(8192)
            var bytesRead: Int
            CipherInputStream(input, cipher).use { cis ->
                while (cis.read(buffer).also { bytesRead = it } != -1) {
                    output.write(buffer, 0, bytesRead)
                }
            }
        }
    }
}

/** ---------- RSA AES key 包装 ---------- **/

fun rsaEncryptAesKey(aesKey: SecretKey, pub: PublicKey): ByteArray {
    val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, pub)
    return cipher.doFinal(aesKey.encoded)
}

fun rsaDecryptAesKey(encryptedAesKey: ByteArray, privateKey: PrivateKey): SecretKey {
    val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
    cipher.init(Cipher.DECRYPT_MODE, privateKey)
    val decryptedKeyBytes = cipher.doFinal(encryptedAesKey)
    return SecretKeySpec(decryptedKeyBytes, "AES")
}

/** ---------- 文件操作 ---------- **/

suspend fun saveTextToFile(
    context: Context,
    uri: Uri,
    text: String
) {
    withContext(Dispatchers.IO) {
        try {
            context.contentResolver.openOutputStream(uri)?.use { outputStream ->
                outputStream.write(text.toByteArray())
            }
        } catch (e: Exception) {
            Log.e("FileSave", "保存文件失败: ${e.message}")
            throw e
        }
    }
}

suspend fun readTextFromFile(context: Context, uri: Uri): String {
    return withContext(Dispatchers.IO) {
        context.contentResolver.openInputStream(uri)?.use { inputStream ->
            inputStream.bufferedReader().use { reader ->
                reader.readText()
            }
        } ?: ""
    }
}

/** ---------- 文件扩展名处理 ---------- **/

fun getOriginalFileName(context: Context, uri: Uri): String {
    var fileName = ""
    context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
        val nameIndex = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
        if (cursor.moveToFirst() && nameIndex != -1) {
            fileName = cursor.getString(nameIndex)
        }
    }
    return fileName
}

fun removeEncryptedExtension(fileName: String): String {
    return if (fileName.endsWith(".encrypted")) {
        fileName.substring(0, fileName.length - 10)
    } else if (fileName.endsWith(".bin")) {
        fileName.substring(0, fileName.length - 4)
    } else {
        fileName
    }
}

/** ---------- 复制到剪贴板 ---------- **/

fun copyToClipboard(context: Context, text: String, label: String = "Encrypted Key") {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val clip = ClipData.newPlainText(label, text)
    clipboard.setPrimaryClip(clip)
    Toast.makeText(context, "已复制到剪贴板", Toast.LENGTH_SHORT).show()
}

/** ---------- Compose UI ---------- **/
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CryptoApp() {
    val ctx = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current

    var generatedPublicKeyPem by remember { mutableStateOf("") }
    var generatedPrivateKeyPem by remember { mutableStateOf("") }
    var encryptPublicKeyPem by remember { mutableStateOf("") }
    var decryptPrivateKeyPem by remember { mutableStateOf("") }
    var encryptedAesKeyB64 by remember { mutableStateOf("") }
    var inputUriEncrypt by remember { mutableStateOf<Uri?>(null) }
    var outputUriEncrypt by remember { mutableStateOf<Uri?>(null) }
    var inputUriDecrypt by remember { mutableStateOf<Uri?>(null) }
    var outputUriDecrypt by remember { mutableStateOf<Uri?>(null) }
    var originalFileName by remember { mutableStateOf("") }
    var isEncrypting by remember { mutableStateOf(false) }
    var isDecrypting by remember { mutableStateOf(false) }
    var showKeyWarning by remember { mutableStateOf(false) }

    val pickFileForEncrypt =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) {
            inputUriEncrypt = it
            if (it != null) {
                originalFileName = getOriginalFileName(ctx, it)
            }
        }

    val createFileForEncrypt =
        rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) {
            outputUriEncrypt = it
        }

    val pickFileForDecrypt =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) {
            inputUriDecrypt = it
        }

    val createFileForDecrypt =
        rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument()) { uri ->
            outputUriDecrypt = uri
        }

    val savePublicKey =
        rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/x-pem-file")) { uri ->
            uri?.let {
                lifecycleOwner.lifecycleScope.launch {
                    try {
                        saveTextToFile(ctx, it, generatedPublicKeyPem)
                        Toast.makeText(ctx, "公钥已保存", Toast.LENGTH_SHORT).show()
                    } catch (e: Exception) {
                        Toast.makeText(ctx, "保存失败: ${e.message}", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }

    val savePrivateKey =
        rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/x-pem-file")) { uri ->
            uri?.let {
                lifecycleOwner.lifecycleScope.launch {
                    try {
                        saveTextToFile(ctx, it, generatedPrivateKeyPem)
                        Toast.makeText(ctx, "私钥已保存", Toast.LENGTH_SHORT).show()
                    } catch (e: Exception) {
                        Toast.makeText(ctx, "保存失败: ${e.message}", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }

    val saveEncryptedAesKey =
        rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
            uri?.let {
                lifecycleOwner.lifecycleScope.launch {
                    try {
                        saveTextToFile(ctx, it, encryptedAesKeyB64)
                        Toast.makeText(ctx, "加密的AES密钥已保存", Toast.LENGTH_SHORT).show()
                        showKeyWarning = false
                    } catch (e: Exception) {
                        Toast.makeText(ctx, "保存失败: ${e.message}", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }

    val loadPublicKeyForEncrypt =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            uri?.let {
                lifecycleOwner.lifecycleScope.launch {
                    try {
                        encryptPublicKeyPem = readTextFromFile(ctx, it)
                        Toast.makeText(ctx, "加密公钥已加载", Toast.LENGTH_SHORT).show()
                    } catch (e: Exception) {
                        Toast.makeText(ctx, "加载公钥失败: ${e.message}", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }

    val loadPrivateKeyForDecrypt =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            uri?.let {
                lifecycleOwner.lifecycleScope.launch {
                    try {
                        decryptPrivateKeyPem = readTextFromFile(ctx, it)
                        Toast.makeText(ctx, "解密私钥已加载", Toast.LENGTH_SHORT).show()
                    } catch (e: Exception) {
                        Toast.makeText(ctx, "加载私钥失败: ${e.message}", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }

    Scaffold(topBar = {
        TopAppBar(title = { Text("Vault密盒") })
    }) { padding ->
        Column(
            modifier = Modifier
                .verticalScroll(rememberScrollState())
                .padding(padding)
                .padding(16.dp)
                .fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text("密钥生成", style = MaterialTheme.typography.headlineSmall)

            Button(onClick = {
                try {
                    val keyPair = generateRSAKeyPair()
                    generatedPublicKeyPem = publicKeyToPem(keyPair.public)
                    generatedPrivateKeyPem = privateKeyToPem(keyPair.private)
                    Toast.makeText(ctx, "生成密钥对成功", Toast.LENGTH_SHORT).show()
                } catch (e: Exception) {
                    e.printStackTrace()
                    Toast.makeText(ctx, "生成失败: ${e.localizedMessage}", Toast.LENGTH_LONG)
                        .show()
                }
            }) {
                Text("生成 RSA 密钥对")
            }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = { savePublicKey.launch("public_key.pem") },
                    enabled = generatedPublicKeyPem.isNotEmpty()
                ) {
                    Text("保存公钥")
                }
                Button(
                    onClick = { savePrivateKey.launch("private_key.pem") },
                    enabled = generatedPrivateKeyPem.isNotEmpty()
                ) {
                    Text("保存私钥")
                }
            }

            OutlinedTextField(
                value = generatedPublicKeyPem,
                onValueChange = { generatedPublicKeyPem = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 120.dp),
                label = { Text("生成的公钥 (PEM)") },
                enabled = false
            )

            OutlinedTextField(
                value = generatedPrivateKeyPem,
                onValueChange = { generatedPrivateKeyPem = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 120.dp),
                label = { Text("生成的私钥 (PEM)") },
                enabled = false
            )

            HorizontalDivider()

            Text("加密部分", style = MaterialTheme.typography.headlineSmall)

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { loadPublicKeyForEncrypt.launch(arrayOf("application/x-pem-file", "text/plain")) }) {
                    Text("加载加密公钥")
                }
                Text(
                    if (encryptPublicKeyPem.isNotEmpty()) "已加载公钥" else "未加载公钥",
                    modifier = Modifier.align(Alignment.CenterVertically)
                )
            }

            OutlinedTextField(
                value = encryptPublicKeyPem,
                onValueChange = { encryptPublicKeyPem = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 120.dp),
                label = { Text("加密公钥 (PEM)") },
                enabled = false
            )

            Row(verticalAlignment = Alignment.CenterVertically) {
                Button(onClick = { pickFileForEncrypt.launch(arrayOf("*/*")) }) {
                    Text("选择文件")
                }
                Spacer(Modifier.width(8.dp))
                Text(
                    inputUriEncrypt?.lastPathSegment ?: "未选择文件",
                    modifier = Modifier.weight(1f)
                )
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                Button(onClick = {
                    val defaultName = if (originalFileName.isNotEmpty()) {
                        "$originalFileName.encrypted"
                    } else {
                        "encrypted.bin"
                    }
                    createFileForEncrypt.launch(defaultName)
                }) {
                    Text("选择输出位置")
                }
                Spacer(Modifier.width(8.dp))
                Text(
                    outputUriEncrypt?.lastPathSegment ?: "未选择输出",
                    modifier = Modifier.weight(1f)
                )
            }

            if (showKeyWarning) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            "⚠️ 重要提醒",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "请务必保存以下加密的AES密钥！没有此密钥将无法解密文件。",
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                        Spacer(Modifier.height(8.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = { saveEncryptedAesKey.launch("encrypted_aes_key.txt") },
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = MaterialTheme.colorScheme.error,
                                    contentColor = MaterialTheme.colorScheme.onError
                                )
                            ) {
                                Text("保存密钥文件")
                            }
                            Button(
                                onClick = { copyToClipboard(ctx, encryptedAesKeyB64, "Encrypted AES Key") },
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = MaterialTheme.colorScheme.error,
                                    contentColor = MaterialTheme.colorScheme.onError
                                )
                            ) {
                                Text("复制密钥")
                            }
                        }
                    }
                }
            }

            if (encryptedAesKeyB64.isNotEmpty()) {
                OutlinedTextField(
                    value = encryptedAesKeyB64,
                    onValueChange = { encryptedAesKeyB64 = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("RSA加密的AES密钥 (Base64)") },
                    trailingIcon = {
                        IconButton(onClick = { copyToClipboard(ctx, encryptedAesKeyB64, "Encrypted AES Key") }) {
                            Icon(
                                imageVector = androidx.compose.material.icons.Icons.Default.ContentCopy,
                                contentDescription = "复制"
                            )
                        }
                    }
                )
            }

            Button(
                onClick = {
                    isEncrypting = true
                    lifecycleOwner.lifecycleScope.launch {
                        try {
                            val pub = pemToPublicKey(encryptPublicKeyPem)
                            if (pub == null) {
                                Toast.makeText(ctx, "请先加载有效的公钥", Toast.LENGTH_SHORT)
                                    .show()
                                return@launch
                            }
                            if (inputUriEncrypt == null || outputUriEncrypt == null) {
                                Toast.makeText(ctx, "请选择输入/输出文件", Toast.LENGTH_SHORT)
                                    .show()
                                return@launch
                            }

                            val aesKey = generateAESKey()
                            encryptFile(ctx, inputUriEncrypt!!, outputUriEncrypt!!, aesKey)
                            val encAesKey = rsaEncryptAesKey(aesKey, pub)

                            encryptedAesKeyB64 = Base64.encodeToString(encAesKey, Base64.NO_WRAP)
                            showKeyWarning = true

                            Toast.makeText(ctx, "加密完成！请保存加密的AES密钥", Toast.LENGTH_LONG).show()
                        } catch (e: Exception) {
                            e.printStackTrace()
                            Toast.makeText(
                                ctx,
                                "加密失败: ${e.localizedMessage}",
                                Toast.LENGTH_LONG
                            ).show()
                        } finally {
                            isEncrypting = false
                        }
                    }
                },
                enabled = !isEncrypting && inputUriEncrypt != null && outputUriEncrypt != null && encryptPublicKeyPem.isNotEmpty()
            ) {
                Text(if (isEncrypting) "加密中..." else "加密文件")
            }

            HorizontalDivider()

            Text("解密部分", style = MaterialTheme.typography.headlineSmall)

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { loadPrivateKeyForDecrypt.launch(arrayOf("application/x-pem-file", "text/plain")) }) {
                    Text("加载解密私钥")
                }
                Text(
                    if (decryptPrivateKeyPem.isNotEmpty()) "已加载私钥" else "未加载私钥",
                    modifier = Modifier.align(Alignment.CenterVertically)
                )
            }

            OutlinedTextField(
                value = decryptPrivateKeyPem,
                onValueChange = { decryptPrivateKeyPem = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 120.dp),
                label = { Text("解密私钥 (PEM)") },
                enabled = false
            )

            OutlinedTextField(
                value = encryptedAesKeyB64,
                onValueChange = { encryptedAesKeyB64 = it },
                label = { Text("被 RSA 加密的 AES Key (Base64)") },
                modifier = Modifier.fillMaxWidth(),
                trailingIcon = {
                    if (encryptedAesKeyB64.isNotEmpty()) {
                        IconButton(onClick = { copyToClipboard(ctx, encryptedAesKeyB64, "Encrypted AES Key") }) {
                            Icon(
                                imageVector = androidx.compose.material.icons.Icons.Default.ContentCopy,
                                contentDescription = "复制"
                            )
                        }
                    }
                }
            )

            Row(verticalAlignment = Alignment.CenterVertically) {
                Button(onClick = { pickFileForDecrypt.launch(arrayOf("*/*")) }) {
                    Text("选择加密文件")
                }
                Spacer(Modifier.width(8.dp))
                Text(
                    inputUriDecrypt?.lastPathSegment ?: "未选择文件",
                    modifier = Modifier.weight(1f)
                )
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                Button(onClick = {
                    val inputFileName = inputUriDecrypt?.lastPathSegment ?: "file"
                    val originalName = removeEncryptedExtension(inputFileName)
                    createFileForDecrypt.launch(originalName)
                }) {
                    Text("选择输出位置")
                }
                Spacer(Modifier.width(8.dp))
                Text(
                    outputUriDecrypt?.lastPathSegment ?: "未选择输出",
                    modifier = Modifier.weight(1f)
                )
            }

            Button(
                onClick = {
                    isDecrypting = true
                    lifecycleOwner.lifecycleScope.launch {
                        try {
                            Log.d("Decrypt", "开始解密过程")
                            Log.d("Decrypt", "私钥PEM长度: ${decryptPrivateKeyPem.length}")
                            Log.d("Decrypt", "加密的AES Key长度: ${encryptedAesKeyB64.length}")

                            val privateKey = pemToPrivateKey(decryptPrivateKeyPem)
                            if (privateKey == null) {
                                Toast.makeText(ctx, "无法解析私钥，请检查格式", Toast.LENGTH_SHORT).show()
                                Log.e("PrivateKey", "PEM内容: $decryptPrivateKeyPem")
                                return@launch
                            }
                            Log.d("Decrypt", "私钥解析成功")

                            if (encryptedAesKeyB64.isBlank()) {
                                Toast.makeText(ctx, "AES Key 为空", Toast.LENGTH_SHORT).show()
                                return@launch
                            }

                            if (inputUriDecrypt == null || outputUriDecrypt == null) {
                                Toast.makeText(ctx, "请选择输入/输出文件", Toast.LENGTH_SHORT).show()
                                return@launch
                            }

                            val encryptedAesKey = Base64.decode(encryptedAesKeyB64, Base64.NO_WRAP)
                            Log.d("Decrypt", "AES Key Base64解码成功，长度: ${encryptedAesKey.size}")

                            val aesKey = rsaDecryptAesKey(encryptedAesKey, privateKey)
                            Log.d("Decrypt", "AES Key RSA解密成功")

                            decryptFile(ctx, inputUriDecrypt!!, outputUriDecrypt!!, aesKey)
                            Toast.makeText(ctx, "解密完成", Toast.LENGTH_SHORT).show()

                        } catch (e: Exception) {
                            e.printStackTrace()
                            Log.e("Decrypt", "解密失败: ${e.message}", e)
                            Toast.makeText(ctx, "解密失败: ${e.message}", Toast.LENGTH_LONG).show()
                        } finally {
                            isDecrypting = false
                        }
                    }
                },
                enabled = !isDecrypting && inputUriDecrypt != null && outputUriDecrypt != null &&
                        encryptedAesKeyB64.isNotBlank() && decryptPrivateKeyPem.isNotEmpty()
            ) {
                Text(if (isDecrypting) "解密中..." else "解密文件")
            }
        }
    }
}