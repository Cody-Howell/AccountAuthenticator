﻿using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AccountAuthenticator;

/// <summary>
/// Provides a few custom methods for working with random strings (perhaps could be named better). 
/// Used in my Authentication libraries. 
/// </summary>
public static class StringHelper {
    private const string Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!_"; // Had to remove many special characters

    /// <summary>
    /// Runs the given string through the SHA256 encoding and converts it out through 
    /// Base 64. "Simple" hash.
    /// </summary>
    /// <returns>Hashed string</returns>
    public static string CustomHash(string s) {
        return Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(s)));
    }

    /// <summary>
    /// Generates a random string of alphanumeric characters with the given length. Includes uppercase, 
    /// lowercase, numbers, !, and _. 
    /// </summary>
    public static string GenerateRandomString(int length = 12) {
        var password = new StringBuilder();
        using var rng = RandomNumberGenerator.Create();
        var buffer = new byte[length];

        rng.GetBytes(buffer);

        for (int i = 0; i < length; i++) {
            var index = buffer[i] % Chars.Length;
            password.Append(Chars[index]);
        }

        return password.ToString();
    }
}
