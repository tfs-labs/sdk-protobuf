


#ifndef __TMPLOG_HPP_
#define __TMPLOG_HPP_

#include <string>
#include <fstream>
#include <iostream>

// #include "include/logging.h"

enum OUTTYPE
{
    file,screen
};

void write_tmplog(const std::string& content, OUTTYPE out = file, const std::string& log_name = "new_tmp.log");


void cast_log(const std::string& content,const std::string & log="cast.log");

#endif
