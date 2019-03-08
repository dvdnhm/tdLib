using Microsoft.AspNetCore.Mvc;
using System;
using Orient.Client;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using Newtonsoft.Json;
using System.Collections.Generic;

namespace dumansLib {
	public class lib {
		public static bool isNull(object param) {
			return string.IsNullOrEmpty(Convert.ToString(param));
		}

		public static string toStr(object obj) {
			return Convert.ToString(obj);
		}

		public static Int32 toInt(object obj) {
			return Convert.ToInt32(obj);
		}

		public static string getRID(object obj) {
			return ((ORID)obj).RID;
		}

		public static string sha256Hash(string data) {
			StringBuilder hashTxt = new StringBuilder();

			using (var hash = SHA256.Create()) {
				Encoding enc = Encoding.UTF8;
				Byte[] result = hash.ComputeHash(enc.GetBytes(data));

				foreach (Byte b in result)
					hashTxt.Append(b.ToString("x2"));
			}

			return hashTxt.ToString();
		}

		public static string encrypt(string text, string keyString) {
			var key = Encoding.UTF8.GetBytes(keyString);

			using (var aesAlg = Aes.Create()) {
				using (var encryptor = aesAlg.CreateEncryptor(key, aesAlg.IV)) {
					using (var msEncrypt = new MemoryStream()) {
						using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
						using (var swEncrypt = new StreamWriter(csEncrypt)) {
							swEncrypt.Write(text);
						}

						var iv = aesAlg.IV;

						var decryptedContent = msEncrypt.ToArray();

						var result = new byte[iv.Length + decryptedContent.Length];

						Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
						Buffer.BlockCopy(decryptedContent, 0, result, iv.Length, decryptedContent.Length);

						return Convert.ToBase64String(result);
					}
				}
			}
		}

		public static string decrypt(string cipherText, string keyString) {
			var fullCipher = Convert.FromBase64String(cipherText);

			var iv = new byte[16];
			var cipher = new byte[16];

			Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
			Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, iv.Length);
			var key = Encoding.UTF8.GetBytes(keyString);

			using (var aesAlg = Aes.Create()) {
				using (var decryptor = aesAlg.CreateDecryptor(key, iv)) {
					string result;
					using (var msDecrypt = new MemoryStream(cipher)) {
						using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read)) {
							using (var srDecrypt = new StreamReader(csDecrypt)) {
								result = srDecrypt.ReadToEnd();
							}
						}
					}

					return result;
				}
			}
		}

		public static string obj2json(object obj, bool ignoreNull = true) {
			if (!ignoreNull) {
				JsonSerializerSettings sett = new JsonSerializerSettings();
				sett.NullValueHandling = NullValueHandling.Include;
				return JsonConvert.SerializeObject(obj, sett);
			}
			return JsonConvert.SerializeObject(obj);
		}

		public static object cleanUp4ODB(Dictionary<string, object> dict) {
			dict.Remove("@ORID");
			dict.Remove("@OVersion");
			dict.Remove("@OType");
			dict.Remove("@OClassId");

			return dict;
		}

		public static void closeDB(ODatabase db) {
			db.Close();
			db.Dispose();
		}
	}
}
