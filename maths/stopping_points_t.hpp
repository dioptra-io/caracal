//
// Created by System Administrator on 2019-05-22.
//

#ifndef HEARTBEAT_STOPPING_POINTS_T_HPP
#define HEARTBEAT_STOPPING_POINTS_T_HPP

#include <vector>

namespace mda_maths{
    /**
     * See https://hal.inria.fr/hal-01787252/document
     * @param n
     * @param epsilon
     * @return
     */
    const std::vector<int> compute_stopping_points(int n, double epsilon);

    constexpr int n_nks = 100000;
    static std::vector<int> nks95 = compute_stopping_points(n_nks, 0.05);

}

#endif //HEARTBEAT_STOPPING_POINTS_T_HPP
