#include "ErrorMessage.h"


ErrorMessage::ErrorMessage(){
    auto id_=std::this_thread::get_id();;
    auto iter=thread_error.find(id_);
    if(iter!=thread_error.end()){
        
    }else{
        thread_error[id_]=new QE;
    }
}
ErrorMessage::~ErrorMessage(){
    for(auto &p:thread_error){
       delete p.second;
    }
}

ErrorMessage::QE * ErrorMessage::getQE(std::thread::id & id){
    ErrorMessage::QE * ret=nullptr;
  
     auto iter=thread_error.find(id);
    if(iter!=thread_error.end()){
        ret= iter->second;
    }else{
        ret=new ErrorMessage::QE;
        thread_error[id]=ret;
    }
   
    return ret;
}
void ErrorMessage::addError(int error,const std::string & errorMessage){
    mutex_error.lock();
    auto id_=std::this_thread::get_id();
    QE* q= getQE(id_);
    q->push({error,errorMessage});
    mutex_error.unlock();
}

std::pair<int,std::string> ErrorMessage::getLastError(){
    mutex_error.lock();
    std::pair<int,std::string> ret(0,"no error");
    auto id_=std::this_thread::get_id();;
    QE* q= getQE(id_);
    if(q->size()>0){
        ret=q->front();
        q->pop();
    }
    mutex_error.unlock();
    return ret;
}
