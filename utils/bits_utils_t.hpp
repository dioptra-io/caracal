//
// Created by System Administrator on 2019-11-14.
//

#ifndef HEARTBEAT_BITS_UTILS_T_HPP
#define HEARTBEAT_BITS_UTILS_T_HPP


namespace utils{
    template<typename Int>
    Int n_last_bits(Int z, std::size_t n){
        return z & ((1 << n) - 1);
    };
}


#endif //HEARTBEAT_BITS_UTILS_T_HPP
