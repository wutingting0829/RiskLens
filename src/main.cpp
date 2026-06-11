// src/main.cpp
// 加入「抽原始碼」功能
// cd ~/func-extractor
// cmake --build build -j
// 跑並存檔: ./build/func_extractor test.c -- -std=c11 > functions.jsonl


#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include "clang/Lex/Lexer.h" //Lexer::getSourceText 需要


using namespace clang;
using namespace clang::tooling;
using namespace llvm;

// 設定 Command Line 參數類別
static cl::OptionCategory MyToolCategory("my-tool-options");

// ========================================================
// 1. Visitor：走訪 AST 並抓 FunctionDecl
// ========================================================

class FindFunctionsVisitor : public RecursiveASTVisitor<FindFunctionsVisitor> {
public:
    explicit FindFunctionsVisitor(ASTContext *Context) : Context(Context) {}
    //當它走到一個 "FunctionDecl" (函數宣告/定義) 時會自動呼叫此函式
    bool VisitFunctionDecl(FunctionDecl *FD){
        //只印出有實作內容 (Body) 的函數定義，忽略單純的 Header 宣告
        if(!FD) return true;
        if(!FD->isThisDeclarationADefinition()) return true; // 排除 forward declaration/redeclaration
        Stmt *Body = FD->getBody();
        if(!Body) return true; //只要「有 body」的 function（排除純宣告）

        const SourceManager &SM = Context->getSourceManager(); //包括主檔案和包含的檔案
        SourceLocation BeginLoc = FD->getBeginLoc(); //是否為無效位置
        if(BeginLoc.isInvalid()) return true;
        // 只抓 main file，避免系統 header / include 的 function 也被抓到
        if(!SM.isWrittenInMainFile(BeginLoc)) return true;

        //取得函數name
        std::string FuncName = FD->getNameInfo().getName().getAsString();

        //取得函式原始碼文字（含 signature + body）
        std::string CodeText = getFunctionSourceText(*FD, SM, Context->getLangOpts());

        //取得位置資訊
        PresumedLoc PBegin = SM.getPresumedLoc(BeginLoc);
        PresumedLoc PEnd = SM.getPresumedLoc(FD->getEndLoc());

        // 若 PresumedLoc 無效（少見），退回用 line number
        unsigned StartLine = PBegin.isValid() ? PBegin.getLine() : SM.getSpellingLineNumber(BeginLoc);
        unsigned EndLine = PEnd.isValid() ? PEnd.getLine() : SM.getSpellingLineNumber(FD->getEndLoc());
        std::string filename = PBegin.isValid() ? std::string(PBegin.getFilename()) : "<unknown>";

        FunctionInfo Info;
        Info.file = filename;
        Info.funcName = FuncName;
        Info.lineStart = StartLine;
        Info.lineEnd = EndLine;
        Info.code = CodeText;

        CallCollector CallVisitor(Context, &Info);
        CallVisitor.TraverseStmt(Body);
        addSecurityOrderingSignals(Info);

        Functions.push_back(std::move(Info));

        return true; //繼續走訪其他 AST 節點

    }

    // 收集 direct call graph，輸出 caller_summary / callee_summary
    void emitJsonLines() {
        std::map<std::string, FunctionInfo *> ByName;
        for (auto &Info : Functions) {
            ByName[Info.funcName] = &Info;
        }

        std::map<std::string, std::vector<CallerEdge>> CallersByCallee;
        for (const auto &Caller : Functions) {
            std::set<std::string> SeenInCaller;
            for (const auto &Call : Caller.calls) {
                if (Call.calleeName.empty()) continue;
                std::string edgeKey = Caller.funcName + "->" + Call.calleeName;
                if (!SeenInCaller.insert(edgeKey).second) continue;

                CallerEdge Edge = buildCallerEdge(Caller, Call);
                CallersByCallee[Call.calleeName].push_back(Edge);
            }
        }

        for (const auto &Info : Functions) {
            // JSONL requires each complete JSON object to occupy exactly one line.
            outs() << "{"
                   << "\"file\":\"" << escapeJson(Info.file) << "\","
                   << "\"func_name\":\"" << escapeJson(Info.funcName) << "\","
                   << "\"line_start\":" << Info.lineStart << ","
                   << "\"line_end\":" << Info.lineEnd << ","
                   << "\"caller_summary\":" << buildCallerSummaryJson(Info, CallersByCallee) << ","
                   << "\"callee_summary\":" << buildCalleeSummaryJson(Info, ByName) << ","
                   << "\"current_function_signals\":" << buildJsonStringArray(Info.currentFunctionSignals) << ","
                   << "\"cross_function_direct_evidence\":"
                   << buildCrossFunctionDirectEvidenceJson(Info.crossFunctionDirectEvidence) << ","
                   << "\"code\":\"" << escapeJson(Info.code) << "\""
                   << "}\n";
        }
    }

private:
    struct CallInfo {
        std::string calleeName;
        std::vector<std::string> argTexts;
    };

    struct DirectEvidence {
        std::string kind;
        std::string lhs;
        std::string calleeName;
        std::string expression;
        std::string evidenceStrength;
        std::string explanation;
        bool boundCheckObserved = false;
    };

    struct FunctionInfo {
        std::string file;
        std::string funcName;
        unsigned lineStart = 0;
        unsigned lineEnd = 0;
        std::string code;
        std::vector<CallInfo> calls;
        std::vector<std::string> currentFunctionSignals;
        std::vector<DirectEvidence> crossFunctionDirectEvidence;
    };

    struct CallerEdge {
        std::string funcName;
        std::string relevance;
        std::string inputOrigin;
        std::string inputPathHint;
        std::string controlPathRole;
        std::vector<std::string> argTexts;
        std::vector<std::string> argumentCategories;
        std::string relationKind = "direct_caller";
        int relevanceScore = 0;
    };

    struct OperationSignal {
        std::string operationClass;
        std::string cweFamily;
        std::string evidence;
    };

    struct CalleeEdge {
        std::string funcName;
        std::string relevance;
        std::string roleHint;
        std::vector<std::string> argTexts;
        std::vector<std::string> argumentCategories;
        std::vector<std::string> dangerSignals;
        std::vector<std::string> localSignals;
         // New taxonomy-guided fields
        std::vector<OperationSignal> operationSignals;
        std::vector<std::string> operationClasses;
        std::vector<std::string> cweFamilies;

        std::string evidenceScope = "downstream_only";
        bool isCurrentFunctionEvidence = false;
        bool isDownstreamEvidence = true;
        int argumentFlowScore = 0;
        int roleMatchScore = 0;
        int dangerSignalScore = 0;
        // New taxonomy-guided scores
        int operationSignalScore = 0;
        int securityContextScore = 0;

        int relevanceScore = 0;
        
        
    };

    ASTContext *Context;
    std::vector<FunctionInfo> Functions;
    //  用 Clang AST CallExpr 抽 callee 與 argument expression
    class CallCollector : public RecursiveASTVisitor<CallCollector> {
    public:
        CallCollector(ASTContext *Context, FunctionInfo *Info) : Context(Context), Info(Info) {}

        bool VisitCallExpr(CallExpr *CE) {
            if (!CE || !Info) return true;

            FunctionDecl *DirectCallee = CE->getDirectCallee();
            std::string CalleeName;
            if (DirectCallee) {
                CalleeName = DirectCallee->getNameInfo().getName().getAsString();
            } else {
                CalleeName = getExprText(CE->getCallee(), Context->getSourceManager(), Context->getLangOpts());
            }
            if (CalleeName.empty()) return true;

            CallInfo Call;
            Call.calleeName = CalleeName;
            for (const Expr *Arg : CE->arguments()) {
                Call.argTexts.push_back(getExprText(Arg, Context->getSourceManager(), Context->getLangOpts()));
            }
            Info->calls.push_back(std::move(Call));
            return true;
        }

        // 會檢查 assignment 是否使用 call return來更新 loop/index 變數，這是 parser 進度控制的 strong signal。
        bool VisitBinaryOperator(BinaryOperator *BO) {
            if (!BO || !Info) return true;
            std::string LHS = getExprText(BO->getLHS(), Context->getSourceManager(), Context->getLangOpts());
            std::string RHS = getExprText(BO->getRHS(), Context->getSourceManager(), Context->getLangOpts());
            if (!assignmentUsesCallReturn(BO, LHS, RHS)) return true;

            std::string Op = BO->getOpcodeStr().str();
            if (LHS.empty() || RHS.empty()) return true;

            std::string CalleeName = getFirstCalleeName(BO->getRHS(), Context);
            std::string Expression = LHS + " " + Op + " " + RHS;
            std::string Signal = "unchecked callee return controls loop progress: " + Expression;
            Info->currentFunctionSignals.push_back(Signal);
            Info->currentFunctionSignals = uniqueStrings(Info->currentFunctionSignals);

            //它不是一般的「callee 有危險操作」；它想標出 跨函式互動造成的 current-function direct evidence。
            DirectEvidence Evidence;
            Evidence.kind = "unchecked_callee_return_controls_loop_progress";
            Evidence.lhs = LHS;
            Evidence.calleeName = CalleeName.empty() ? "unknown" : CalleeName;
            Evidence.expression = Expression;
            Evidence.evidenceStrength = "strong";
            Evidence.explanation =
                "The current function updates its own loop/index/progress variable using a callee return value without an observed local bounds/progress check. "
                "This is direct evidence for the current function because parser traversal/progress control occurs in the current function body.";
            Evidence.boundCheckObserved = false;

            bool Seen = false;
            for (const auto &Existing : Info->crossFunctionDirectEvidence) {
                if (Existing.kind == Evidence.kind && Existing.expression == Evidence.expression) {
                    Seen = true;
                    break;
                }
            }
            if (!Seen) Info->crossFunctionDirectEvidence.push_back(Evidence);
            return true;
        }

    private:
        ASTContext *Context;
        FunctionInfo *Info;

        class CallPresenceVisitor : public RecursiveASTVisitor<CallPresenceVisitor> {
        public:
            bool found = false;

            bool VisitCallExpr(CallExpr *CE) {
                if (CE) found = true;
                return false;
            }
        };

        static bool subtreeContainsCall(Stmt *S) {
            if (!S) return false;
            CallPresenceVisitor Visitor;
            Visitor.TraverseStmt(S);
            return Visitor.found;
        }

        class FirstCallNameVisitor : public RecursiveASTVisitor<FirstCallNameVisitor> {
        public:
            explicit FirstCallNameVisitor(ASTContext *Context) : Context(Context) {}

            bool VisitCallExpr(CallExpr *CE) {
                if (!CE || !calleeName.empty()) return false;

                if (FunctionDecl *FD = CE->getDirectCallee()) {
                    calleeName = FD->getNameInfo().getName().getAsString();
                } else if (Context) {
                    calleeName = getExprText(CE->getCallee(), Context->getSourceManager(), Context->getLangOpts());
                }
                return false;
            }

            std::string calleeName;

        private:
            ASTContext *Context;
        };

        static std::string getFirstCalleeName(Stmt *S, ASTContext *Context) {
            if (!S || !Context) return "";
            FirstCallNameVisitor Visitor(Context);
            Visitor.TraverseStmt(S);
            return Visitor.calleeName;
        }

        static bool looksLikeProgressVariable(const std::string &LHS, const std::string &RHS) {
            std::string Name = lowerCopy(LHS);
            std::string Right = lowerCopy(RHS);
            if (containsAny(Name, {"cursor", "pos", "position", "idx", "index", "offset", "off", "read", "consume", "consumed", "remain", "remaining", "progress", "nread"})) {
                return true;
            }
            if ((Name == "i" || Name == "j" || Name == "k" || Name == "n") && Right.find(Name) != std::string::npos) {
                return true;
            }
            return false;
        }

        static bool assignmentUsesCallReturn(BinaryOperator *BO, const std::string &LHS, const std::string &RHS) {
            if (!BO) return false;

            BinaryOperatorKind Opcode = BO->getOpcode();
            if (Opcode == BO_AddAssign || Opcode == BO_SubAssign) {
                return subtreeContainsCall(BO->getRHS());
            }

            return Opcode == BO_Assign
                && subtreeContainsCall(BO->getRHS())
                && looksLikeProgressVariable(LHS, RHS);
        }
    };

    static bool callNameLooksBoundaryTransition(const std::string &FuncName) {
        std::string Name = lowerCopy(FuncName);
        return containsAny(Name, {
            "pivot_root", "unpivot", "chroot", "runchroot", "setns", "mount",
            "chdir", "fchdir", "setuid", "seteuid", "setreuid", "setresuid",
            "setgid", "setegid", "setregid", "setresgid", "setgroups",
            "initgroups", "set_perms", "restore_perms", "capset"
        });
    }

    static bool callNameLooksAuthorityDependentResolution(const std::string &FuncName) {
        std::string Name = lowerCopy(FuncName);
        return containsAny(Name, {
            "resolve", "resolve_cmnd", "find_path", "find_editor", "lookup",
            "getpwnam", "getpwuid", "getgrnam", "getgrgid", "sudo_getpw",
            "sudo_getgr", "nss", "realpath", "canonical", "open_conf_path",
            "open", "stat", "lstat", "fstat", "readlink", "sudo_secure"
        });
    }

    static void addSecurityOrderingSignals(FunctionInfo &Info) {
        for (size_t I = 0; I < Info.calls.size(); ++I) {
            const CallInfo &BoundaryCall = Info.calls[I];
            if (!callNameLooksBoundaryTransition(BoundaryCall.calleeName)) continue;

            for (size_t J = I + 1; J < Info.calls.size(); ++J) {
                const CallInfo &ResolutionCall = Info.calls[J];
                if (!callNameLooksAuthorityDependentResolution(ResolutionCall.calleeName)) continue;

                std::string Expression = BoundaryCall.calleeName + " -> " + ResolutionCall.calleeName;
                std::string Signal =
                    "security-sensitive boundary transition around authority-dependent resolution: " +
                    Expression;
                Info.currentFunctionSignals.push_back(Signal);
                Info.currentFunctionSignals = uniqueStrings(Info.currentFunctionSignals);

                DirectEvidence Evidence;
                Evidence.kind = "security_boundary_transition_around_resolution";
                Evidence.lhs = "security boundary state";
                Evidence.calleeName = ResolutionCall.calleeName;
                Evidence.expression = Expression;
                Evidence.evidenceStrength = "strong";
                Evidence.explanation =
                    "The current function locally performs a security-sensitive boundary transition before or around "
                    "name, path, command, or authority-dependent resolution. Treat this ordering as direct current-function "
                    "evidence because the security boundary state controls how the later lookup is interpreted.";
                Evidence.boundCheckObserved = false;

                bool Seen = false;
                for (const auto &Existing : Info.crossFunctionDirectEvidence) {
                    if (Existing.kind == Evidence.kind && Existing.expression == Evidence.expression) {
                        Seen = true;
                        break;
                    }
                }
                if (!Seen) Info.crossFunctionDirectEvidence.push_back(Evidence);
                break;
            }
        }
    }

    //JSON 跳脫函式
    static std::string escapeJson(const std::string &input){
        std::string output;
        output.reserve(input.size() + 16);
        auto hex = [](unsigned char x) -> char {
            return (x < 10) ? ('0' + x) : ('a' + (x - 10));
        };
        for(unsigned char c : input){
            switch (c){
                case '\"': output += "\\\""; break; // 處理雙引號
                case '\\': output += "\\\\"; break; // 處理反斜線
                case '\n': output += "\\n"; break;  // 處理換行
                case '\r': output += "\\r"; break;
                case '\t': output += "\\t"; break;  // 處理 Tab
                case '\b': output += "\\b";  break;
                case '\f': output += "\\f";  break;
                default:
                    if (c < 0x20) {
                        output += "\\u00";
                        output += hex((c >> 4) & 0x0F);
                        output += hex(c & 0x0F);
                    } else {
                        output += static_cast<char>(c);
                    }
            }
        }
        return output;
    }

    static std::string lowerCopy(std::string Value) {
        std::transform(Value.begin(), Value.end(), Value.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return Value;
    }

    static bool containsAny(const std::string &Haystack, const std::vector<std::string> &Needles) {
        for (const auto &Needle : Needles) {
            if (Haystack.find(Needle) != std::string::npos) return true;
        }
        return false;
    }

    static std::string joinStrings(const std::vector<std::string> &Values, const std::string &Sep) {
        std::ostringstream OS;
        for (size_t I = 0; I < Values.size(); ++I) {
            if (I) OS << Sep;
            OS << Values[I];
        }
        return OS.str();
    }

    static std::vector<std::string> uniqueStrings(const std::vector<std::string> &Values) {
        std::vector<std::string> Result;
        std::set<std::string> Seen;
        for (const auto &Value : Values) {
            if (Seen.insert(Value).second) Result.push_back(Value);
        }
        return Result;
    }

    static std::string getExprText(const Expr *E, const SourceManager &SM, const LangOptions &LO) {
        if (!E) return "";
        CharSourceRange CSR = CharSourceRange::getTokenRange(E->getSourceRange());
        bool Invalid = false;
        StringRef Text = Lexer::getSourceText(CSR, SM, LO, &Invalid);
        if (Invalid) return "";
        return Text.str();
    }

    static std::string classifyInputOrigin(const std::vector<std::string> &ArgTexts) {
        std::string Combined = lowerCopy(joinStrings(ArgTexts, " "));
        if (containsAny(Combined, {"request", "req", "http", "uri", "header", "body", "socket", "recv", "read", "packet", "buf", "buffer", "data", "input", "chunk"})) {
            return "syntactic input-like argument";
        }
        if (containsAny(Combined, {"parser", "parse", "token", "cursor", "offset", "pos", "len", "length", "size", "tag", "action", "field", "state"})) {
            return "parser path or derived parser state";
        }
        if (containsAny(Combined, {"argv", "env", "user", "file", "path", "stdin", "malicious", "tainted"})) {
            return "syntactic user/file-like argument";
        }
        if (ArgTexts.empty()) return "no call arguments";
        return "unclear from call arguments";
    }

    static std::string neutralInputOriginHint(const std::string &InputOrigin) {
        if (InputOrigin == "syntactic input-like argument" || InputOrigin == "syntactic user/file-like argument") {
            return "syntactic input-like argument detected";
        }
        if (InputOrigin == "parser path or derived parser state") {
            return "parser-derived argument pattern detected";
        }
        if (InputOrigin == "no call arguments") {
            return "no call arguments";
        }
        return "unclear from syntax";
    }

    static std::string summarizeCallerRelevance(const std::vector<std::string> &ArgTexts, const std::string &InputOrigin) {
        std::string Combined = lowerCopy(joinStrings(ArgTexts, " "));
        std::vector<std::string> Details;
        if (containsAny(Combined, {"buf", "buffer", "data", "ptr", "pointer"})) Details.push_back("buffer/pointer argument");
        if (containsAny(Combined, {"len", "length", "size", "count", "max", "remain", "remaining"})) Details.push_back("length/size argument");
        if (containsAny(Combined, {"off", "offset", "pos", "position", "cursor", "idx", "index"})) Details.push_back("offset/progress argument");
        if (containsAny(Combined, {"state", "ctx", "context", "parser"})) Details.push_back("state/context argument");
        if (containsAny(Combined, {"argv", "env", "user", "request", "input", "file", "packet", "chunk"})) Details.push_back("externally influenced argument");

        if (Details.empty()) {
            return "calls current function; argument source is not obvious from syntax";
        }
        return "passes " + joinStrings(uniqueStrings(Details), ", ") + " into current function";
    }

    static std::vector<std::string> classifyArgumentCategories(const std::vector<std::string> &ArgTexts) {
        std::string Combined = lowerCopy(joinStrings(ArgTexts, " "));
        std::vector<std::string> Categories;
        if (ArgTexts.empty()) Categories.push_back("no arguments");
        if (containsAny(Combined, {"dc", "ctx", "context", "state", "parser"})) Categories.push_back("parser state");
        if (containsAny(Combined, {"act", "action", "tag", "field", "opcode", "bytecode", "data", "chunk"})) Categories.push_back("action data");
        if (containsAny(Combined, {"len", "length", "size", "count", "max", "remain", "remaining"})) Categories.push_back("length-like value");
        if (containsAny(Combined, {"off", "offset", "pos", "position", "cursor", "idx", "index"})) Categories.push_back("offset/progress value");
        if (containsAny(Combined, {"buf", "buffer", "ptr", "pointer", "dst", "dest", "src"})) Categories.push_back("buffer/pointer");
        if (Categories.empty()) Categories.push_back("unclear from syntax");
        
        // New taxonomy-guided categories
        if (containsAny(Combined, {"path", "file", "dir", "fd", "root", "cwd"}))
            Categories.push_back("path/file resource");

        if (containsAny(Combined, {"cmd", "cmnd", "command", "argv", "exec"}))
            Categories.push_back("command/execution data");

        if (containsAny(Combined, {"uid", "gid", "user", "group", "runas", "cred", "role"}))
            Categories.push_back("identity/principal");

        if (containsAny(Combined, {"chroot", "root", "runchroot", "pivot", "namespace", "mount", "cwd"}))
            Categories.push_back("filesystem namespace state");

        if (containsAny(Combined, {"nss", "pam", "passwd", "shadow", "config", "policy", "lookup"}))
            Categories.push_back("trust/config lookup");

        if (containsAny(Combined, {"auth", "permission", "policy", "rule", "allow", "deny", "check"}))
            Categories.push_back("auth/policy decision");

        if (containsAny(Combined, {"env", "environ", "locale", "loader", "ld_preload"}))
            Categories.push_back("environment/runtime context");

        if (containsAny(Combined, {"cert", "x509", "ssl", "tls", "asn1", "crypto"}))
            Categories.push_back("crypto/certificate state");

        if (Categories.empty()) Categories.push_back("unclear from syntax");

        return uniqueStrings(Categories);
    }

    static bool callerNameLooksRelevant(const std::string &FuncName) {
        std::string Name = lowerCopy(FuncName);
        return containsAny(Name, {"parser", "parse", "read", "decode", "load", "handle", "process", "scan", "check", "validate", "dispatch", "main"});
    }

    static bool callerNameLooksLikeEntry(const std::string &FuncName) {
        std::string Name = lowerCopy(FuncName);
        return containsAny(Name, {"main", "read", "recv", "request", "handle_request", "entry"});
    }

    static bool callerNameLooksParserLike(const std::string &FuncName) {
        std::string Name = lowerCopy(FuncName);
        return containsAny(Name, {"parser", "parse", "decompile", "decode", "load", "scan", "check", "validate", "dispatch"});
    }

    static bool isLoggingOrDebugHelper(const std::string &FuncName) {
        std::string Name = lowerCopy(FuncName);
        return containsAny(Name, {
            "log", "debug", "trace", "warn", "warning", "error", "fatal",
            "print", "printf", "fprintf", "snprintf", "syslog", "audit"
        });
    }

    static bool argsLookInputLike(const std::string &Args) {
        return containsAny(Args, {"buf", "buffer", "data", "input", "chunk", "packet", "file", "argv", "env", "user", "request", "stdin"});
    }

    static bool argsLookStructuredParserLike(const std::string &Args) {
        return containsAny(Args, {"state", "ctx", "context", "parser", "action", "tag", "field", "opcode", "len", "length", "size", "offset", "cursor"});
    }

    static int scoreCallerRelevance(const FunctionInfo &Caller, const CallInfo &Call, const std::string &InputOrigin) {
        std::string Args = lowerCopy(joinStrings(Call.argTexts, " "));
        int Score = 0;
        if (containsAny(Args, {"buf", "buffer", "data", "ptr", "pointer"})) Score += 3;
        if (containsAny(Args, {"len", "length", "size", "count", "max", "remain", "remaining"})) Score += 3;
        if (containsAny(Args, {"off", "offset", "pos", "position", "cursor", "idx", "index"})) Score += 3;
        if (containsAny(Args, {"state", "ctx", "context", "parser"})) Score += 3;
        if (callerNameLooksRelevant(Caller.funcName)) Score += 2;
        if (callerNameLooksLikeEntry(Caller.funcName) && argsLookInputLike(Args)) Score += 2;
        if (InputOrigin == "syntactic input-like argument" || InputOrigin == "syntactic user/file-like argument") Score += 2;
        if (InputOrigin == "parser path or derived parser state") Score += 1;
        return Score;
    }

    static std::string classifyInputPathHint(const FunctionInfo &Caller, const CallInfo &Call, const std::string &InputOrigin) {
        std::string Args = lowerCopy(joinStrings(Call.argTexts, " "));
        bool HasInputArgs = argsLookInputLike(Args);
        bool HasParserArgs = argsLookStructuredParserLike(Args);
        bool EntryName = callerNameLooksLikeEntry(Caller.funcName);
        bool ParserName = callerNameLooksParserLike(Caller.funcName);

        if (EntryName && HasInputArgs) return "strong";
        if (ParserName && (HasInputArgs || HasParserArgs)) return "medium";
        return "weak";
    }

    static std::string summarizeControlPathRole(const FunctionInfo &Caller, const CallInfo &Call, int RelevanceScore) {
        std::string Args = lowerCopy(joinStrings(Call.argTexts, " "));
        if (callerNameLooksLikeEntry(Caller.funcName) && argsLookInputLike(Args)) {
            return "entry-like caller with input-like arguments";
        }
        if (callerNameLooksRelevant(Caller.funcName) || containsAny(Args, {"state", "ctx", "parser", "offset", "cursor", "len", "length"})) {
            return "on the upstream parser/control path";
        }
        if (RelevanceScore >= 4) {
            return "receiving security-relevant data from its caller";
        }
        return "connected by a direct call, but control-path importance is unclear";
    }

    //cleanup helper 判斷
    static bool isCleanupOrFreeHelper(const std::string &Name) {
        std::string N = lowerCopy(Name);
        return containsAny(N, {
            "free",
            "delref",
            "close",
            "cleanup",
            "destroy",
            "release"
        });
    }

    //高價值 security operation 判斷，這些 operation 的出現通常是安全檢查、權限變更、重要資源存取等關鍵安全行為的 strong signal
    static bool hasHighValueSecurityOperation(const std::vector<std::string> &OperationClasses) {
        std::string Ops = lowerCopy(joinStrings(OperationClasses, " "));
        return containsAny(Ops, {
            "filesystem_namespace_transition",
            "privilege_identity_transition",
            "trust_config_lookup",
            "dynamic_code_loading",
            "auth_policy_gate",
            "command_execution",
            "crypto_certificate_validation"
        });
    }

    static CallerEdge buildCallerEdge(const FunctionInfo &Caller, const CallInfo &Call) {
        CallerEdge Edge;
        Edge.funcName = Caller.funcName;
        Edge.inputOrigin = classifyInputOrigin(Call.argTexts);
        Edge.inputPathHint = classifyInputPathHint(Caller, Call, Edge.inputOrigin);
        Edge.argTexts = Call.argTexts;
        Edge.argumentCategories = classifyArgumentCategories(Call.argTexts);
        Edge.relevance = summarizeCallerRelevance(Call.argTexts, Edge.inputOrigin);
        Edge.relevanceScore = scoreCallerRelevance(Caller, Call, Edge.inputOrigin);
        Edge.controlPathRole = summarizeControlPathRole(Caller, Call, Edge.relevanceScore);
        return Edge;
    }

    //避免同一個 function 因為同時出現 chroot 和 pivot_root，重複加入多個一樣的 filesystem_namespace_transition，造成分數膨脹。
    static void addOperationSignal(
        std::vector<OperationSignal> &Signals,
        const std::string &OperationClass,
        const std::string &CweFamily,
        const std::string &Evidence
    ){
        for(const auto &S : Signals){
            if(S.operationClass == OperationClass && S.cweFamily == CweFamily) return;
        }

        OperationSignal Signal;
        Signal.operationClass = OperationClass;
        Signal.cweFamily = CweFamily;
        Signal.evidence = Evidence;
        Signals.push_back(Signal);
    }

    // 針對被呼叫者（Callee）的分析。它會掃描被呼叫函數的名字和原始碼，尋找既有的危險特徵：
    static std::vector<std::string> detectDangerSignals(const std::string &FuncName, const std::string &Code) {
        std::string Text = lowerCopy(FuncName + " " + Code);
        std::vector<std::string> Signals;
        if (containsAny(Text, {"memcpy", "memmove", "bcopy", "strcpy", "strncpy", "strcat", "strncat", "sprintf", "snprintf", "copy"})) {
            Signals.push_back("memory copy");
        }
        if (containsAny(Text, {"strcpy", "strncpy", "strcat", "strncat", "strlen", "strcmp", "strncmp", "snprintf", "sprintf", "strchr", "strstr"})) {
            Signals.push_back("string handling");
        }
        if (containsAny(Text, {"memcpy", "memmove", "strncpy", "strncat", "snprintf", "sprintf", "len", "length", "size", "count", "nbytes"})) {
            Signals.push_back("length-dependent operation");
        }
        if (containsAny(Text, {"malloc", "calloc", "realloc", "alloc", "new "})) Signals.push_back("allocation");
        if (containsAny(Text, {"push", "pop", "stack", "stackptr", "stack_ptr", "top", "peek"})) Signals.push_back("stack manipulation");
        if (containsAny(Text, {"len", "length", "size", "remain", "remaining", "consumed", "chunk_size", "content_length", "nread", "read_bytes"})) Signals.push_back("length/remaining/consumed update");
        if (containsAny(Text, {"state", "status", "mode", "phase", "switch", "case"})) Signals.push_back("parser state update");
        if (containsAny(Text, {"*p", "->data", "write", "put", "append", "emit", "dst", "dest", "sprintf", "snprintf", "strcpy", "strncpy", "memcpy", "memmove"})) Signals.push_back("buffer write");
        if (containsAny(Text, {"pos", "cursor", "offset", "advance", "next", "consume", "read", "p++", "++p"})) Signals.push_back("parser progress update");
        if (containsAny(Text, {"cast", "static_cast", "reinterpret_cast", "(int)", "(char", "(unsigned", "(size_t", "(uint", "(long", "(short", "type", "enum"})) Signals.push_back("type conversion/cast");
        if (containsAny(Text, {"valid", "validate", "check", "assert", "return 0", "return 1", "error", "invalid", "reject"})) Signals.push_back("validation logic");
        return uniqueStrings(Signals);
    }

    // Taxonomy-guided operation signals are kept separate from legacy string danger signals.
    static std::vector<OperationSignal> detectOperationSignals(const std::string &FuncName, const std::string &Code) {
        std::string Text = lowerCopy(FuncName + " " + Code);
        std::vector<OperationSignal> Signals;

        // 1. Memory write / buffer operation
        if(containsAny(Text,{  "memcpy", "memmove", "bcopy", "strcpy", "strncpy","strcat", "strncat", "sprintf", "snprintf","write", "append", "dst", "dest", "src"})){
            addOperationSignal(
                Signals, 
                "memory_write",
                "memory_safety",
                "Function appears to perform memory, string, or buffer write operations.");
        }
            // 2. Size / index / length computation
        if (containsAny(Text, {
            "len", "length", "size", "count", "nbytes","idx", "index", "offset", "remain", "remaining", "malloc", "calloc", "realloc"})) {
            addOperationSignal(
                Signals,
                "size_index_arithmetic",
                "integer_size",
                "Function uses size, length, index, offset, or allocation-related values.");
        }

        // 3. Allocation / lifetime
        if (containsAny(Text, {"malloc", "calloc", "realloc", "free", "new ", "delete "})) {
            addOperationSignal(
                Signals,
                "allocation_lifetime",
                "resource_lifecycle",
                "Function manages allocation, deallocation, or object lifetime.");
        }

        // 4. Parser / decoder
        if (containsAny(Text, {"parse", "parser", "decode", "decompile", "read","next", "advance", "consume", "token", "tag", "field", "opcode", "chunk", "state"})) {
            addOperationSignal(
                Signals,
                 "parser_decoder",
                "input_validation_parser",
                "Function appears to parse, decode, or advance structured input state.");
        }

        // 5. Path / file / resource resolution
        if (containsAny(Text, {"path", "file", "dir", "fd", "open", "fopen", "stat", "lstat", "realpath", "canonical", "resolve", "symlink", "readlink"})) {
            addOperationSignal(
                Signals,
                "path_file_resolution",
                "path_file_resource",
                "Function appears to resolve paths, files, directories, or filesystem resources.");
        }

        // 6. Command execution / command resolution
        if (containsAny(Text, {"system", "exec", "execve", "execl", "execv", "popen", "command", "cmd", "cmnd", "argv"})) {
            addOperationSignal(
                Signals,
                "command_execution",
                "injection_command_execution",
                "Function appears to execute, construct, or resolve commands.");
        }

        // 7. Privilege / identity transition
        if (containsAny(Text, {"setuid", "seteuid", "setreuid", "setresuid", "setgid", "setegid", "setregid", "setresgid", "setgroups", "initgroups", "uid", "gid", "user", "group", "runas", "cred", "capset", "cap_"})) {
            addOperationSignal(
                Signals,
                "privilege_identity_transition",
                "privilege_access_control",
                "Function appears to manipulate user/group identity, credentials, or privilege state.");
        }

        // 8. Filesystem namespace / root transition
        if (containsAny(Text, {"chroot", "pivot_root", "unpivot", "rootdir", "runchroot", "chdir", "fchdir", "setns", "mount", "namespace", "cwd"})) {
            addOperationSignal(
                Signals,
                "filesystem_namespace_transition",
                "privilege_access_control",
                "Function appears to change filesystem root, working directory, or namespace context.");
        }

        // 9. Trust/config lookup: NSS/PAM/passwd/group/config/policy
        if (containsAny(Text, { "nss", "pam", "passwd", "shadow", "group", "getpwnam", "getpwuid", "getgrnam", "getgrgid", "lookup", "nsswitch", "config", "policy"})) {
            addOperationSignal(
                Signals,
                "trust_config_lookup",
                "trust_boundary_security_decision",
                "Function appears to read identity, policy, configuration, or trusted lookup data.");
        }

        // 10. Dynamic code loading
        if (containsAny(Text, { "dlopen", "dlsym", "loadlibrary", "module", "plugin", ".so", "shared object", "library"})) {
            addOperationSignal(
                Signals,
                "dynamic_code_loading",
                "trust_boundary_security_decision",
                "Function appears to load external code, modules, plugins, or dynamic libraries.");
        }

        // 11.  Authorization / policy gate
        if (containsAny(Text, { "check", "validate", "verify", "match", "allow", "deny", "policy", "permission", "authorize", "auth", "sudoers", "rule"})) {
            addOperationSignal(
                Signals,
                "auth_policy_gate",
                "privilege_access_control",
                "Function appears to participate in authorization, policy, validation, or permission checks.");
        }
        
        // 12. Crypto / certificate validation
        if (containsAny(Text, { "x509", "cert", "certificate", "ssl", "tls", "verify", "signature", "crypto", "asn1", "punycode", "name constraint"})) {
            addOperationSignal(
                Signals,
                "crypto_certificate_validation",
                "crypto_auth_certificate",
                "Function appears related to cryptographic, certificate, or security validation logic.");
        }

        // 13. Race / ordering / locking
        if (containsAny(Text, { "lock", "unlock", "mutex", "race", "atomic", "before", "after", "toctou"})) {
            addOperationSignal(
                Signals,
                "race_ordering",
                "race_ordering_toctou",
                "Function appears to involve synchronization, ordering, or check-use timing.");
        }

        // 14. Environment / runtime context
        if (containsAny(Text, { "env", "environ", "getenv", "setenv", "putenv", "locale", "loader", "ld_preload", "home", "shell" })) {
            addOperationSignal(
                Signals,
                "environment_runtime_context",
                "trust_boundary_security_decision",
                "Function appears to depend on environment or runtime context.");
        }

        return Signals;
    }

    //輸出可統計欄位
    static std::vector<std::string> extractOperationClasses(const std::vector<OperationSignal> &Signals){
        std::vector<std::string> Result;
        for(const auto &S : Signals){
            Result.push_back(S.operationClass);
        }
        return uniqueStrings(Result);
    }

    static std::vector<std::string> extractCweFamilies(const std::vector<OperationSignal> &Signals){
        std::vector<std::string> Result;
        for (const auto &S : Signals) {
            Result.push_back(S.cweFamily);
        }
        return uniqueStrings(Result);
    }

    static std::vector<std::string> summarizeOperationSignals(const std::vector<OperationSignal> &Signals){
        std::vector<std::string> Result;
        for (const auto &S : Signals) {
            Result.push_back(S.operationClass + " -> " + S.cweFamily);
        }
        return uniqueStrings(Result);
    }

    

    static std::string summarizeCalleeRelevance(const std::vector<std::string> &Signals, const std::vector<std::string> &OperationClasses) {
        std::vector<std::string> Parts;
        if (!Signals.empty()) {
            Parts.push_back("local signals: " + joinStrings(Signals, ", "));
        }
        if (!OperationClasses.empty()) {
            Parts.push_back("operation signals: " + joinStrings(OperationClasses, ", "));
        }
        if (Parts.empty()) return "has no obvious local signals";
        return joinStrings(Parts, " "); 
    }

    static std::string summarizeCalleeRoleHint(const std::vector<std::string> &Signals, const std::vector<std::string> &OperationClasses) {
        std::string SignalText = lowerCopy(joinStrings(Signals, " "));
        std::string OperationText = lowerCopy(joinStrings(OperationClasses, " "));
        if (containsAny(OperationText, {"filesystem_namespace_transition", "privilege_identity_transition"})) {
            return "downstream privilege or namespace state-transition helper";
        }

        if (containsAny(OperationText, {"trust_config_lookup", "dynamic_code_loading"})) {
            return "downstream trust/config lookup or dynamic loading helper";
        }

        if (containsAny(OperationText, {"auth_policy_gate"})) {
            return "downstream authorization or policy gate helper";
        }

        if (containsAny(OperationText, {"path_file_resolution", "command_execution"})) {
            return "downstream path or command resolution helper";
        }

        if (containsAny(OperationText, {"crypto_certificate_validation"})) {
            return "downstream crypto/certificate validation helper";
        }       

        if (containsAny(OperationText, {"memory_write", "allocation_lifetime"})) {
            return "downstream memory/data operation helper";
        }

        if (containsAny(SignalText, {"validation logic", "parser state update", "type conversion/cast"})) {
            return "downstream validation/state helper";
        }

        if (containsAny(SignalText, {"memory copy", "allocation", "buffer write", "string handling", "stack manipulation"})) {
            return "downstream dangerous primitive helper";
        }
        return "direct helper";
    }

    static int scoreCalleeDangerSignals(const std::vector<std::string> &Signals) {
        int Score = 0;
        for (const auto &Signal : Signals) {
            if (Signal == "memory copy" || Signal == "buffer write") Score += 2;
            else if (Signal == "allocation" || Signal == "string handling" || Signal == "stack manipulation") Score += 1;
            else if (Signal == "parser state update" || Signal == "length/remaining/consumed update" || Signal == "parser progress update") Score += 1;
            else if (Signal == "type conversion/cast" || Signal == "validation logic" || Signal == "length-dependent operation") Score += 1;
        }
        return std::min(Score, 2);
    }

    static int scoreCalleeOperationSignals(const std::vector<OperationSignal> &Signals) {
        int Score = 0;

        for (const auto &Signal : Signals) {
            const std::string &Cls = Signal.operationClass;

            if (
                Cls == "memory_write" ||
                Cls == "command_execution" ||
                Cls == "privilege_identity_transition" ||
                Cls == "filesystem_namespace_transition" ||
                Cls == "dynamic_code_loading"
            ) {
                Score += 2;
            } else if (
                Cls == "trust_config_lookup" ||
                Cls == "auth_policy_gate" ||
                Cls == "path_file_resolution" ||
                Cls == "crypto_certificate_validation"
            ) {
                Score += 2;
            } else if (
                Cls == "size_index_arithmetic" ||
                Cls == "allocation_lifetime" ||
                Cls == "parser_decoder" ||
                Cls == "race_ordering" ||
                Cls == "environment_runtime_context"
            ) {
                Score += 1;
            }     
        }
        return std::min(Score, 6);
    }

    

    static int scoreCalleeArgumentFlow(const std::vector<std::string> &Categories) {
        int Score = 0;
        for (const auto &Category : Categories) {
            if (Category == "buffer/pointer") Score += 4;
            else if (Category == "length-like value") Score += 4;
            else if (Category == "parser state") Score += 3;
            else if (Category == "action data") Score += 3;
            else if (Category == "offset/progress value") Score += 3;

            // New taxonomy-guided categories
            else if (Category == "path/file resource") Score += 4;
            else if (Category == "command/execution data") Score += 4;
            else if (Category == "identity/principal") Score += 4;
            else if (Category == "filesystem namespace state") Score += 5;
            else if (Category == "trust/config lookup") Score += 5;
            else if (Category == "auth/policy decision") Score += 4;
            else if (Category == "environment/runtime context") Score += 4;
            else if (Category == "crypto/certificate state") Score += 4;
        }
        return std::min(Score, 8);
    }

    //有些 function 沒有明顯 memory operation，但位於 security-critical path 上，仍然值得關注。例如一個叫 check_policy 的 function，裡面沒有明顯的 memory operation，但它的名字和內容都強烈暗示它在做安全檢查。這種情況下，我們可以給它一個額外的分數加成，以反映它在安全上下文中的重要性。
    static int scoreSecurityContext(const std::string &FuncName, const std::string &Code) {
        
        if (isLoggingOrDebugHelper(FuncName)) {
            return 0;
        }

        std::string Text = lowerCopy(FuncName + " " + Code);
        int Score = 0;


        if (containsAny(Text, {
            "sudo", "sudoers", "policy", "auth", "permission",
            "check", "validate", "verify", "match", "allow", "deny"
        })) {
            Score += 1;
        }

        if (containsAny(Text, {
            "root", "uid", "gid", "runas", "priv", "credential",
            "chroot", "nss", "pam"
        })) {
            Score += 1;
        }

        if (containsAny(Text, {
            "x509", "cert", "ssl", "tls", "crypto", "signature"
        })) {
            Score += 1;
        }

        return std::min(Score, 2);
    }


    

    static int scoreCalleeRoleMatch(
        const std::string &FuncName,
        const std::vector<std::string> &Categories,
        const std::vector<std::string> &Signals,
        const std::vector<OperationSignal> &OperationSignals
    ) {
        std::string Name = lowerCopy(FuncName);
        std::string CategoryText = lowerCopy(joinStrings(Categories, " "));
        std::string SignalText = lowerCopy(joinStrings(Signals, " "));
        std::string OperationText = lowerCopy(joinStrings(extractOperationClasses(OperationSignals), " "));
        int Score = 0;

        // Existing memory/parser-oriented role matching 
        if (
            containsAny(CategoryText, {"buffer", "pointer"})
            && (containsAny(SignalText, {"memory copy", "buffer write", "string handling"}) || containsAny(Name, {"copy", "str", "mem", "put", "write"}))
        ) {
            Score += 3;
        }
        if (
            containsAny(CategoryText, {"length-like"})
            && (containsAny(SignalText, {"length", "remaining", "consumed"}) || containsAny(Name, {"len", "length", "size", "count", "strlen"}))
        ) {
            Score += 3;
        }
        if (
            containsAny(CategoryText, {"parser state", "offset", "progress"})
            && (containsAny(SignalText, {"parser state", "parser progress", "validation", "type conversion"}) || containsAny(Name, {"parse", "decompile", "read", "next", "advance", "state"}))
        ) {
            Score += 3;
        }
        if (
            containsAny(CategoryText, {"action data"})
            && (containsAny(SignalText, {"parser state", "validation", "type conversion", "string handling"}) || containsAny(Name, {"action", "tag", "field", "opcode", "get"}))
        ) {
            Score += 3;
        }

        // New taxonomy-guided role matching
        if (
            containsAny(CategoryText, {"path/file resource"})
            && containsAny(OperationText, {"path_file_resolution", "filesystem_namespace_transition"})
        ) {
            Score += 3;
        }

        if (
            containsAny(CategoryText, {"command/execution data"})
            && containsAny(OperationText, {"command_execution", "path_file_resolution"})
        ) {
            Score += 3;
        }

        if (
            containsAny(CategoryText, {"identity/principal"})
            && containsAny(OperationText, {"privilege_identity_transition", "trust_config_lookup", "auth_policy_gate"})
        ) {
            Score += 3;
        }

        if (
            containsAny(CategoryText, {"filesystem namespace state"})
            && containsAny(OperationText, {"filesystem_namespace_transition", "path_file_resolution", "trust_config_lookup"})
        ) {
            Score += 3;
        }

        if (
            containsAny(CategoryText, {"trust/config lookup"})
            && containsAny(OperationText, {"trust_config_lookup", "dynamic_code_loading", "auth_policy_gate"})
        ) {
            Score += 3;
        }

        if (
            containsAny(CategoryText, {"auth/policy decision"})
            && containsAny(OperationText, {"auth_policy_gate", "privilege_identity_transition", "trust_config_lookup"})
        ) {
            Score += 3;
        }

        if (
            containsAny(CategoryText, {"environment/runtime context"})
            && containsAny(OperationText, {"environment_runtime_context", "dynamic_code_loading", "trust_config_lookup"})
        ) {
            Score += 3;
        }

        if (
            containsAny(CategoryText, {"crypto/certificate state"})
            && containsAny(OperationText, {"crypto_certificate_validation", "parser_decoder"})
        ) {
            Score += 3;
        }

        return std::min(Score, 8);
    }

    static std::vector<std::string> neutralizeCalleeSignals(const std::vector<std::string> &Signals) {
        std::vector<std::string> Neutral;
        for (const auto &Signal : Signals) {
            if (Signal == "memory copy" || Signal == "buffer write") Neutral.push_back("memory/buffer operation");
            else if (Signal == "length-dependent operation" || Signal == "length/remaining/consumed update") Neutral.push_back("length-related logic");
            else if (Signal == "parser state update") Neutral.push_back("parser state logic");
            else if (Signal == "parser progress update") Neutral.push_back("parser progress logic");
            else if (Signal == "stack manipulation") Neutral.push_back("stack operation");
            else Neutral.push_back(Signal);
        }

        return uniqueStrings(Neutral);
    }


    static CalleeEdge buildCalleeEdge(const CallInfo &Call, const std::map<std::string, FunctionInfo *> &ByName) {
        auto It = ByName.find(Call.calleeName);
        std::string CalleeCode = (It != ByName.end()) ? It->second->code : "";
        std::vector<std::string> Signals = detectDangerSignals(Call.calleeName, CalleeCode);
        std::vector<OperationSignal> OperationSignals = detectOperationSignals(Call.calleeName, CalleeCode);

        CalleeEdge Edge;
        Edge.funcName = Call.calleeName;
        Edge.argTexts = Call.argTexts;
        Edge.argumentCategories = classifyArgumentCategories(Call.argTexts);
        Edge.dangerSignals = Signals;
        Edge.localSignals = neutralizeCalleeSignals(Signals);
        // New taxonomy-guided fields
        Edge.operationSignals = OperationSignals;
        Edge.operationClasses = extractOperationClasses(OperationSignals);
        Edge.cweFamilies = extractCweFamilies(OperationSignals);
        Edge.relevance = summarizeCalleeRelevance(Signals, Edge.operationClasses);
        Edge.roleHint = summarizeCalleeRoleHint(Signals, Edge.operationClasses);

        Edge.argumentFlowScore = scoreCalleeArgumentFlow(Edge.argumentCategories);
        Edge.roleMatchScore = scoreCalleeRoleMatch(Edge.funcName, Edge.argumentCategories, Signals, OperationSignals);
        Edge.dangerSignalScore = scoreCalleeDangerSignals(Signals);
        Edge.operationSignalScore = scoreCalleeOperationSignals(OperationSignals);
        Edge.securityContextScore = scoreSecurityContext(Edge.funcName, CalleeCode);

        // New relevance formula:
        Edge.relevanceScore = Edge.argumentFlowScore + Edge.roleMatchScore + Edge.dangerSignalScore + Edge.securityContextScore;

        // Cleanup/free helpers are useful supporting context,
        // but should not dominate top-k unless they contain high-value security operations.
        if (isCleanupOrFreeHelper(Edge.funcName) &&
            !hasHighValueSecurityOperation(Edge.operationClasses)) {
            Edge.relevanceScore = std::min(Edge.relevanceScore, 10);
        }     
        
        return Edge;
    }

    static constexpr size_t kMaxCallContextEdges = 5;

    static std::vector<CalleeEdge> selectTopCallees(const std::vector<CalleeEdge> &Edges) {
        std::vector<CalleeEdge> Ranked;
        for (const auto &Edge : Edges) {
            if (Edge.relevanceScore > 0) Ranked.push_back(Edge);
        }
        std::stable_sort(Ranked.begin(), Ranked.end(), [](const CalleeEdge &A, const CalleeEdge &B) {
            if (A.relevanceScore != B.relevanceScore) return A.relevanceScore > B.relevanceScore;
            if (A.argumentFlowScore != B.argumentFlowScore) return A.argumentFlowScore > B.argumentFlowScore;
            if (A.roleMatchScore != B.roleMatchScore) return A.roleMatchScore > B.roleMatchScore;
            if (A.operationSignalScore != B.operationSignalScore) return A.operationSignalScore > B.operationSignalScore;
            if (A.securityContextScore != B.securityContextScore) return A.securityContextScore > B.securityContextScore;
            return A.funcName < B.funcName; // Tie-breaker for consistent ordering
        });

        if (Ranked.size() > kMaxCallContextEdges) Ranked.resize(kMaxCallContextEdges);
        return Ranked;
    }

    static std::vector<std::string> buildCalleeSummaryLines(const std::vector<CalleeEdge> &TopEdges) {
        std::vector<std::string> Lines;
        if (TopEdges.empty()) {
            Lines.push_back("No direct callee with local signals was selected for this function.");
            Lines.push_back("Note: callee signals are downstream evidence only unless the callee return value controls current-function progress.");
            return Lines;
        }

        for (const auto &Edge : TopEdges) {
            std::string Args = Edge.argTexts.empty() ? "none" : joinStrings(Edge.argTexts, ", ");
            std::string Categories = Edge.argumentCategories.empty() ? "unclear from syntax" : joinStrings(Edge.argumentCategories, ", ");
            std::string Signals = Edge.localSignals.empty() ? "none observed" : joinStrings(Edge.localSignals, ", ");
            std::string Ops = Edge.operationClasses.empty() ? "none observed" : joinStrings(Edge.operationClasses, ", ");
            std::string Families = Edge.cweFamilies.empty() ? "none observed" : joinStrings(Edge.cweFamilies, ", ");

            Lines.push_back("Calls " + Edge.funcName + " with arguments: " + Args + ".");
            Lines.push_back("Passed argument categories: " + Categories + ".");
            Lines.push_back("Callee has local signals: " + Signals + ".");
            Lines.push_back("Callee has operation signals: " + Ops + ".");
            Lines.push_back("Callee has CWE families: " + Families + ".");
        }
        Lines.push_back("Note: callee signals are downstream evidence only unless the callee return value controls current-function progress.");
        return Lines;
    }

    static std::string buildJsonStringArray(const std::vector<std::string> &Values) {
        std::ostringstream OS;
        OS << "[";
        for (size_t I = 0; I < Values.size(); ++I) {
            if (I) OS << ", ";
            OS << "\"" << escapeJson(Values[I]) << "\"";
        }
        OS << "]";
        return OS.str();
    }

    static std::string buildCrossFunctionDirectEvidenceJson(const std::vector<DirectEvidence> &EvidenceList) {
        std::vector<std::string> Lines;

        if (EvidenceList.empty()) {
            Lines.push_back("No cross-function direct evidence was detected in the current function body.");
        } else {
            for (const auto &Evidence : EvidenceList) {
                if (Evidence.kind == "security_boundary_transition_around_resolution") {
                    Lines.push_back(
                        "Current function performs " + Evidence.expression +
                        "; treat this security ordering as direct current-function evidence, not merely callee supporting evidence."
                    );
                    Lines.push_back(
                        "Pattern: boundary transition -> name/path/command/authority-dependent resolution."
                    );
                } else {
                    Lines.push_back(
                        "Current function updates " + Evidence.lhs +
                        " using return value from " + Evidence.calleeName +
                        "; treat this as direct current-function evidence, not merely callee supporting evidence."
                    );
                    Lines.push_back(
                        "Pattern: callee return value -> current loop/index/progress variable -> next traversal step."
                    );
                }
            }
        }

        std::ostringstream OS;
        OS << "{\"summary_lines\": " << buildJsonStringArray(Lines)
           << ", \"patterns\": [";

        for (size_t I = 0; I < EvidenceList.size(); ++I) {
            if (I) OS << ", ";
            const auto &Evidence = EvidenceList[I];
            OS << "{"
               << "\"kind\": \"" << escapeJson(Evidence.kind) << "\", "
               << "\"lhs\": \"" << escapeJson(Evidence.lhs) << "\", "
               << "\"callee\": \"" << escapeJson(Evidence.calleeName) << "\", "
               << "\"expression\": \"" << escapeJson(Evidence.expression) << "\", "
               << "\"bound_check_observed\": " << (Evidence.boundCheckObserved ? "true" : "false") << ", "
               << "\"evidence_strength\": \"" << escapeJson(Evidence.evidenceStrength) << "\", "
               << "\"explanation\": \"" << escapeJson(Evidence.explanation) << "\", "
               << "\"ranking_effect\": \"may increase root_cause_likelihood, decision_or_validation_risk, state_ordering_consistency_risk, and failure_trigger_plausibility when current-function ordering controls traversal, authority, or resolution semantics\""
               << "}";
        }

        OS << "]}";
        return OS.str();
    }

    static std::vector<CallerEdge> selectTopCallers(const std::vector<CallerEdge> &Edges) {
        std::vector<CallerEdge> Ranked = Edges;
        std::stable_sort(Ranked.begin(), Ranked.end(), [](const CallerEdge &A, const CallerEdge &B) {
            return A.relevanceScore > B.relevanceScore;
        });
        if (Ranked.size() > kMaxCallContextEdges) Ranked.resize(kMaxCallContextEdges);
        return Ranked;
    }

    static std::string buildCallerSummaryLine(const std::vector<CallerEdge> &TopEdges) {
        if (TopEdges.empty()) return "No direct caller was found for this function in the current translation unit.";

        const CallerEdge &Top = TopEdges.front();
        std::string Args = Top.argTexts.empty() ? "none" : joinStrings(Top.argTexts, ", ");
        std::string Categories = Top.argumentCategories.empty() ? "unclear from syntax" : joinStrings(Top.argumentCategories, ", ");
        std::string Line = "Caller relation: " + Top.funcName + " calls current function with arguments: " + Args + ".";
        Line += " Passed argument categories: " + Categories + ".";
        if (TopEdges.size() > 1) {
            std::vector<std::string> OtherNames;
            for (size_t I = 1; I < TopEdges.size(); ++I) OtherNames.push_back(TopEdges[I].funcName);
            Line += " Other selected caller: " + joinStrings(OtherNames, ", ") + ".";
        }
        return Line;
    }

    static std::vector<std::string> buildCallerSummaryLines(const std::vector<CallerEdge> &TopEdges) {
        std::vector<std::string> Lines;
        Lines.push_back(buildCallerSummaryLine(TopEdges));

        if (TopEdges.empty()) {
            Lines.push_back("Input origin is unclear from direct caller context.");
            Lines.push_back("Current function may be an entry point or may be called outside the current translation unit.");
            return Lines;
        }

        const CallerEdge &Top = TopEdges.front();
        Lines.push_back("Input path evidence level: " + Top.inputPathHint + ".");
        Lines.push_back("Note: caller context is upstream relation evidence only, not direct evidence for the current function body.");
        return Lines;
    }

    static std::string buildCallerSummaryJson(
        const FunctionInfo &Info,
        const std::map<std::string, std::vector<CallerEdge>> &CallersByCallee
    ) {
        auto It = CallersByCallee.find(Info.funcName);
        std::vector<CallerEdge> AllEdges = (It != CallersByCallee.end()) ? It->second : std::vector<CallerEdge>{};
        std::vector<CallerEdge> TopEdges = selectTopCallers(AllEdges);
        std::vector<std::string> SummaryLines = buildCallerSummaryLines(TopEdges);

        std::ostringstream OS;
        OS << "{\"num_callers\": " << AllEdges.size()
           << ", \"summary_lines\": " << buildJsonStringArray(SummaryLines)
           << ", \"callers\": [";
        for (size_t I = 0; I < TopEdges.size(); ++I) {
            if (I) OS << ", ";
            OS << "{"
               << "\"func_name\": \"" << escapeJson(TopEdges[I].funcName) << "\", "
               << "\"role_hint\": \"" << escapeJson(TopEdges[I].controlPathRole) << "\", "
               << "\"relation_kind\": \"" << escapeJson(TopEdges[I].relationKind) << "\", "
               << "\"relevance\": \"" << escapeJson(TopEdges[I].relevance) << "\", "
               << "\"arg_texts\": " << buildJsonStringArray(TopEdges[I].argTexts) << ", "
               << "\"argument_categories\": " << buildJsonStringArray(TopEdges[I].argumentCategories) << ", "
               << "\"input_path_hint\": \"" << escapeJson(TopEdges[I].inputPathHint) << "\", "
               << "\"input_path_evidence\": \"" << escapeJson(TopEdges[I].inputPathHint) << "\", "
               << "\"input_origin_hint\": \"" << escapeJson(neutralInputOriginHint(TopEdges[I].inputOrigin)) << "\", "
               << "\"relevance_score\": " << TopEdges[I].relevanceScore
               << "}";
        }
        OS << "]}";
        return OS.str();
    }

    static std::string buildCalleeSummaryJson(const FunctionInfo &Info, const std::map<std::string, FunctionInfo *> &ByName) {
        std::vector<CallInfo> UniqueCalls;
        std::set<std::string> Seen;
        for (const auto &Call : Info.calls) {
            if (Seen.insert(Call.calleeName).second) UniqueCalls.push_back(Call);
        }

        std::vector<CalleeEdge> AllEdges;
        for (const auto &Call : UniqueCalls) {
            AllEdges.push_back(buildCalleeEdge(Call, ByName));
        }
        std::vector<CalleeEdge> TopEdges = selectTopCallees(AllEdges);
        std::vector<std::string> SummaryLines = buildCalleeSummaryLines(TopEdges);

        std::ostringstream OS;
        OS << "{\"num_callees\": " << UniqueCalls.size()
           << ", \"summary_lines\": " << buildJsonStringArray(SummaryLines)
           << ", \"callees\": [";
        for (size_t I = 0; I < TopEdges.size(); ++I) {
            if (I) OS << ", ";
            OS << "{"
                << "\"func_name\": \"" << escapeJson(TopEdges[I].funcName) << "\", "
                << "\"role_hint\": \"" << escapeJson(TopEdges[I].roleHint) << "\", "
                << "\"relevance\": \"" << escapeJson(TopEdges[I].relevance) << "\", "
                << "\"arg_texts\": " << buildJsonStringArray(TopEdges[I].argTexts) << ", "
                << "\"argument_categories\": " << buildJsonStringArray(TopEdges[I].argumentCategories) << ", "

                // Existing fields
                << "\"local_signals\": " << buildJsonStringArray(TopEdges[I].localSignals) << ", "

                // New taxonomy-guided fields
                << "\"operation_signals\": " << buildJsonStringArray(TopEdges[I].operationClasses) << ", "
                << "\"weakness_families\": " << buildJsonStringArray(TopEdges[I].cweFamilies) << ", "
                << "\"operation_classes\": " << buildJsonStringArray(TopEdges[I].operationClasses) << ", "
                << "\"cwe_families\": " << buildJsonStringArray(TopEdges[I].cweFamilies) << ", "

                << "\"evidence_scope\": \"" << escapeJson(TopEdges[I].evidenceScope) << "\", "
                << "\"is_current_function_evidence\": " << (TopEdges[I].isCurrentFunctionEvidence ? "true" : "false") << ", "
                << "\"is_downstream_evidence\": " << (TopEdges[I].isDownstreamEvidence ? "true" : "false") << ", "
                << "\"downstream_signal_hint\": " << buildJsonStringArray(TopEdges[I].dangerSignals) << ", "

                // Existing scores
                << "\"argument_flow_score\": " << TopEdges[I].argumentFlowScore << ", "
                << "\"role_match_score\": " << TopEdges[I].roleMatchScore << ", "
                << "\"local_signal_score\": " << TopEdges[I].dangerSignalScore << ", "

                // New taxonomy-guided scores
                << "\"operation_signal_score\": " << TopEdges[I].operationSignalScore << ", "
                << "\"security_context_score\": " << TopEdges[I].securityContextScore << ", "

                // Final callee relevance score
                << "\"relevance_score\": " << TopEdges[I].relevanceScore
                << "}";

            
        }
        OS << "]}";
        return OS.str();
    }
   

    // ========================================================
    // 2. 從 SourceRange 抽出原始碼文字
    // ========================================================
    static std::string getFunctionSourceText(const FunctionDecl &FD, const SourceManager &SM, const LangOptions &LO){
        //FunctionDecl 的 SourceRange 通常涵蓋 signature + body
        SourceRange SR = FD.getSourceRange();

        // getEndLoc() 指向的是最後一個 Token 的「開頭」（也就是 '}' 的左邊）。
        // 我們需要的是 '}' 的「右邊」。
        // 所以要用 CharSourceRange::getTokenRange 讓 Lexer 知道我們要包含最後那個 Token。

        CharSourceRange CSR = CharSourceRange::getTokenRange(SR);      
        bool Invalid = false;  

        // Lexer::getSourceText 是 Clang 提供的一個靜態函式，用於從指定的 CharSourceRange 中提取原始程式碼文字。
        //static StringRef getSourceText(CharSourceRange Range, const SourceManager &SM, const LangOptions &LangOpts, bool *Invalid = nullptr);            
        StringRef Text = Lexer::getSourceText(CSR, SM, LO, &Invalid); 
        
        if(Invalid) return "<Error extracting source text>";
        return Text.str(); //轉成 std::string 回傳

    }

    
};

// ========================================================
// 2. ASTConsumer: 負責接收 ASTContext 並啟動 Visitor
// ========================================================
class FindFunctionsConsumer : public ASTConsumer {
    public:
        explicit FindFunctionsConsumer(ASTContext *Context) : Visitor(Context) {}
    
        //(Translation Unit) 被 Parse 完後，會呼叫這裡
        virtual void HandleTranslationUnit(ASTContext &Context) override {
            //啟動 AST Visitor 開始走訪 AST
            Visitor.TraverseDecl(Context.getTranslationUnitDecl());
            Visitor.emitJsonLines();
        }
    private:
        FindFunctionsVisitor Visitor;
};


//  ASTConsumer：TranslationUnit 建好後啟動 Visitor
class FindFunctionsAction : public ASTFrontendAction {
    public:
        std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI, StringRef file) override {
            return std::make_unique<FindFunctionsConsumer>(&CI.getASTContext());
        }
    };



int main(int argc, const char **argv){
    // 解析命令列參數（LLVM 16 正確寫法）
    auto ExpectedParser = CommonOptionsParser::create(argc, argv, MyToolCategory);
    if (!ExpectedParser) {
        errs() << ExpectedParser.takeError();
        return 1;
    }
    CommonOptionsParser &OptionsParser = ExpectedParser.get();

    // 建立 ClangTool
    ClangTool Tool(
        OptionsParser.getCompilations(),
        OptionsParser.getSourcePathList()
    );

    // 5. 執行工具
    return Tool.run(newFrontendActionFactory<FindFunctionsAction>().get());
}
