#ifndef __LOG_MODIFIERS_H__
#define __LOG_MODIFIERS_H__

#include <string>
#include "virtual_modifiers.h"

namespace LogModifiers
{

class ReplaceBackslash : public ReplaceSubContiners<std::string>
{
public:
    ReplaceBackslash() { init(&src, &dst); }

private:
    std::string src = "\\";
    std::string dst = "\\\\";
};

class ReplaceCR : public ReplaceSubContiners<std::string>
{
public:
    ReplaceCR() { init(&src, &dst); }

private:
    std::string src = "\r";
    std::string dst = "\\r";
};

class ReplaceLF : public ReplaceSubContiners<std::string>
{
public:
    ReplaceLF() { init(&src, &dst); }

private:
    std::string src = "\n";
    std::string dst = "\\n";
};

class ReplaceDoubleOuotes : public ReplaceSubContiners<std::string>
{
public:
    ReplaceDoubleOuotes() { init(&src, &dst); }

private:
    std::string src = "\"";
    std::string dst = "\\\"";
};

class ReplaceQuote : public ReplaceSubContiners<std::string>
{
public:
    ReplaceQuote() { init(&src, &dst); }

private:
    std::string src = "'";
    std::string dst = "\\'";
};

class ReplaceClosingBrace : public ReplaceSubContiners<std::string>
{
public:
    ReplaceClosingBrace() { init(&src, &dst); }

private:
    std::string src = "]";
    std::string dst = "\\]";
};

class ReplaceEqualSign : public ReplaceSubContiners<std::string>
{
public:
    ReplaceEqualSign() { init(&src, &dst); }

private:
    std::string src = "=";
    std::string dst = "\\=";
};

} // namesapce LogModifiers

#endif // __LOG_MODIFIERS_H__
