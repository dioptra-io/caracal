//
// Created by System Administrator on 2019-05-31.
//

#include <stopping_points_t.hpp>
#include <cmath>

#include <iostream>
namespace mda_maths{

    const std::vector<int> compute_stopping_points(int n, double epsilon){
        std::vector<int> nks;
        nks.push_back(0);
        for (int k = 2; k < n; ++k){

            int nk = ceil(log10(epsilon/double(k))/log10((double(k-1))/double(k)));
            nks.push_back(nk);
        }
        return nks;
    }
}
