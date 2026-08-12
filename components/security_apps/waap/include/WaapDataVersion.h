#pragma once

#include <fstream>
#include <string>
#include "cereal/archives/json.hpp"

class WaapDataVersion
{
public:
    WaapDataVersion(const std::string &path)
    {
        try {
            std::ifstream file(path);
            if (!file.is_open()) {
                m_buildNumber = -1;
                return;
            }
            cereal::JSONInputArchive archive(file);
            this->load(archive);
        } catch (...) {
            m_buildNumber = -1;
            return;
        }
    }

    int
    getBuildNumber() const
    {
        return m_buildNumber;
    }

private:
    void
    load(cereal::JSONInputArchive &ar)
    {
        try {
            std::string buildNumberStr;
            ar(cereal::make_nvp("build_number", buildNumberStr));
            m_buildNumber = std::stoi(buildNumberStr);
        } catch (...) {
            m_buildNumber = -1;
        }
    }

    int m_buildNumber = 0;
};
