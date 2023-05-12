#pragma once
#pragma once

#define STRING_XOR_KEY 0x2b
#define WSTRING_XOR_KEY 0x2b5c
#define OBF(str) \
    []() -> char* { \
        constexpr auto size = sizeof(str)/sizeof(str[0]); \
        constexpr auto obfuscated_str = obfuscator<size>(str); \
        static char original_string[size]; \
        obfuscated_str.deobfoscate((unsigned char *)original_string); \
        return original_string; \
    }()

#define OBF_LEN(str,size) \
    []() -> char* { \
        constexpr auto obfuscated_str = obfuscator<size>(str); \
        static char original_string[size]; \
        obfuscated_str.deobfoscate((unsigned char *)original_string); \
        return original_string; \
    }()

#define WOBF(str) \
    []() -> wchar_t* { \
        constexpr auto size = sizeof(str)/sizeof(str[0]); \
        constexpr auto obfuscated_str = wobfuscator<size>(str); \
        static wchar_t original_string[size]; \
        obfuscated_str.deobfoscate((wchar_t *)original_string); \
        return original_string; \
    }()

#define WOBF_LEN(str,size) \
    []() -> wchar_t* { \
        constexpr auto obfuscated_str = wobfuscator<size>(str); \
        static wchar_t original_string[size]; \
        obfuscated_str.deobfoscate((wchar_t *)original_string); \
        return original_string; \
    }()

template <unsigned int N>
struct obfuscator {

    char m_data[N] = { 0 };

    constexpr obfuscator(const char* data) {
        /*
         * Implement encryption algorithm here.
         * Here we have simple XOR algorithm.
         */
        for (unsigned int i = 0; i < N; i++) {
            m_data[i] = data[i] ^ STRING_XOR_KEY;
        }
    }

    void deobfoscate(unsigned char* des) const {
        int i = 0;
        do {
            des[i] = m_data[i] ^ STRING_XOR_KEY;
            i++;
        } while (des[i - 1]);
    }
};

template <unsigned int N>
struct wobfuscator {

    wchar_t m_data[N] = { 0 };

    constexpr wobfuscator(const wchar_t* data) {
        /*
         * Implement encryption algorithm here.
         * Here we have simple XOR algorithm.
         */
        for (unsigned int i = 0; i < N; i++) {
            m_data[i] = data[i] ^ WSTRING_XOR_KEY;
        }
    }

    void deobfoscate(wchar_t* des) const {
        int i = 0;
        do {
            des[i] = m_data[i] ^ WSTRING_XOR_KEY;
            i++;
        } while (des[i - 1]);
    }
};