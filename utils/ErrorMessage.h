#ifndef __MSAGGDKDK__
#define __MSAGGDKDK__
#include <thread>
#include <map>
#include <queue>
#include <mutex>
#include <string>
#define MSG(msg) std::string(msg)+__FILE__+std::to_string(__LINE__)

class ErrorMessage{
    public:
    using QE=std::queue<std::pair<int,std::string>>;
    ErrorMessage();
    ~ErrorMessage();
    void addError(int error,const std::string & errorMessage);

    std::pair<int,std::string> getLastError();



    private:
    std::mutex mutex_error;
    QE * getQE(std::thread::id & id);
    std::map<std::thread::id,QE *> thread_error;

};


#endif