#include <cstdint>

namespace rage
{
    constexpr uint32_t atStringHash(const char *str, uint32_t seed = 0)
    {
        const char *v3 = str;
        if (str[0] == '"' )
            v3 = str + 1;

        for (char i = *v3; *v3; i = *v3 )
        {
            if ( *str == '"' && i == '"' )
                break;

            ++v3;

            if ((i - 65) > 25)
            {
                if ( i == '\\' )
                    i = '/';
            }
            else
            {
                i += 32;
            }

            seed = ((1025 * (seed + i)) >> 6) ^ (1025 * (seed + i));
        }

        return 32769 * ((9 * seed) ^ ((9 * seed) >> 11));
    }
}