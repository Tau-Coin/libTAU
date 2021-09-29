/*

Copyright (c) 2021, Xianshui Sheng
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/crypto.hpp"
#include "libTAU/hex.hpp"

#ifdef TORRENT_USE_OPENSSL
#include <openssl/aes.h>
#endif

#include <cstring>
#include <string>

namespace libTAU {

	namespace aux {

#ifdef TORRENT_USE_OPENSSL

		namespace {

			static constexpr std::size_t AES_KEY_LENGTH = 32; // aes-256

			static const std::string crypto_error_key_length = "key length error";
			static const std::string crypto_error_padding = "padding error";
			static const std::string crypto_error_unpadding = "unpadding error";
			static const std::string crypto_error_set_key = "set key error";
			static const std::string crypto_error_input_length = "decrypt input length error";

			// OPENSSL AES block size is 128 bites(16 bytes),
			// so we choose PKCS7 as padding algorithm.
			bool pkcs7_padding(std::string& in, std::uint8_t modulus)
			{
				std::uint8_t pad_byte = modulus - (in.size() % modulus);
				for (uint8_t i = 0; i < pad_byte; i++)
				{
					in.push_back(static_cast<char>(pad_byte));
				}

				return true;
			}

			bool pkcs7_unpadding(std::string& in, std::uint8_t modulus)
			{
				if (in.size() < modulus)
				{
					return false;
				}

				if (in.size() % modulus != 0 && in.size() >= modulus)
				{
					return false;
				}

				std::size_t pad_len = in[in.size() - 1];
				try
				{
					in.erase(in.size() - pad_len);
				}
				catch (...)
				{
					return false;
				}

				return true;
			}

		} // anonymous namespace
#endif

		bool aes_encrypt(const std::string& in
			, std::string& out
			, const std::string& key
			, std::string& err_str)
		{
#ifdef TORRENT_USE_OPENSSL
			if (key.size() != AES_KEY_LENGTH)
			{
				err_str.assign(crypto_error_key_length);
				return false;
			}

			std::string in_copy = in;

			if (!pkcs7_padding(in_copy, AES_BLOCK_SIZE))
			{
				err_str.assign(crypto_error_padding);
				return false;
			}

			AES_KEY aes_key;
			if (AES_set_encrypt_key((unsigned char *)key.c_str()
					, AES_KEY_LENGTH * 8, &aes_key) != 0)
			{
				err_str.assign(crypto_error_set_key);
				return false;
			}

			unsigned char *src = (unsigned char *)in_copy.c_str();

			// OPENSSL AES API is programed in c lang, so here
			// encrypted buffer size must be 'AES_BLOCK_SIZE + 1'.
			unsigned char dest[AES_BLOCK_SIZE + 1] = {'\0'};
			for (int i = 0; i < in_copy.size() / AES_BLOCK_SIZE; ++i)
			{
				std::memset(dest, 0x0, AES_BLOCK_SIZE + 1);
				AES_ecb_encrypt(src + i * AES_BLOCK_SIZE
					, dest
					, &aes_key
					, AES_ENCRYPT);

				// Must append AES_BLOCK_SIZE bytes.
				// If 'AES_BLOCK_SIZE' bytes isn't specified,
				// append bytes util meeting '\0'.
				out.append((char *)dest, AES_BLOCK_SIZE);
			}

			return true;
#else
			out = in;
			return true;
#endif
		}

		bool aes_decrypt(const std::string& in
			, std::string& out
			, const std::string& key
			, std::string& err_str)
		{
#ifdef TORRENT_USE_OPENSSL
			if (key.size() != AES_KEY_LENGTH)
			{
				err_str.assign(crypto_error_key_length);
				return false;
			}

			if (in.size() % AES_BLOCK_SIZE != 0)
			{
				err_str.assign(crypto_error_input_length);
				return false;
			}

			AES_KEY aes_key;
			if (AES_set_decrypt_key((unsigned char *)key.c_str()
				, AES_KEY_LENGTH * 8, &aes_key) != 0)
			{
				err_str.assign(crypto_error_set_key);
				return false;
			}

			unsigned char *src = (unsigned char *)in.c_str();

			// OPENSSL AES API is programed in c lang, so here
			// decrypted buffer size must be 'AES_BLOCK_SIZE + 1'.
			unsigned char dest[AES_BLOCK_SIZE + 1] = {'\0'};
			for (int i = 0; i < in.size() / AES_BLOCK_SIZE; ++i)
			{
				std::memset(dest, 0x0, AES_BLOCK_SIZE + 1);
				AES_ecb_encrypt(src + i * AES_BLOCK_SIZE
					, dest
					, &aes_key
					, AES_DECRYPT);

				// Must append AES_BLOCK_SIZE bytes.
				// If 'AES_BLOCK_SIZE' bytes isn't specified,
				// append bytes util meeting '\0'.
				out.append((char *)dest, AES_BLOCK_SIZE);
			}

			if (!pkcs7_unpadding(out, AES_BLOCK_SIZE))
			{
				std::string errstr = crypto_error_unpadding;
				errstr += ", decrypted hex str: ";
				errstr += aux::to_hex(out);
				err_str.assign(errstr);
				return false;
			}

			return true;
#else
			out = in;
			return true;
#endif
		}

	} // aux namespace

}
