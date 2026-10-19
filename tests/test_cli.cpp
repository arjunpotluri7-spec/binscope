// Command-line behaviour: exit codes, options, safe output writing.
#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "cli.hpp"
#include "helpers.hpp"
#include "io.hpp"
#include "mini_json.hpp"

#if !defined(_WIN32)
#include <sys/stat.h>
#endif

using bs_test::sample_path;
namespace fs = std::filesystem;

namespace {

struct Run {
    int code = -1;
    std::string out;
    std::string err;
};

Run run(const std::vector<std::string>& args) {
    std::ostringstream out;
    std::ostringstream err;
    Run r;
    r.code = binscope::cli::run(args, out, err);
    r.out = out.str();
    r.err = err.str();
    return r;
}

class TempDir {
public:
    TempDir() {
        std::random_device rd;
        path_ = fs::temp_directory_path() / ("binscope-test-" + std::to_string(rd()));
        fs::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    [[nodiscard]] std::string file(const std::string& name) const {
        return (path_ / name).string();
    }

private:
    fs::path path_;
};

const std::string kHardenedElf = sample_path("synthetic/elf64_hardened.so");
const std::string kPackedElf = sample_path("synthetic/elf64_packed_like.elf");
const std::string kHardenedPe = sample_path("synthetic/pe64_hardened.exe");
const std::string kPackedPe = sample_path("synthetic/pe64_packed_like.exe");

}  // namespace

TEST(Cli, VersionAndHelp) {
    auto r = run({"--version"});
    EXPECT_EQ(r.code, 0);
    EXPECT_EQ(r.out, "binscope 0.1.0\n");
    r = run({"--help"});
    EXPECT_EQ(r.code, 0);
    EXPECT_NE(r.out.find("Exit codes:"), std::string::npos);
    r = run({"inspect", "--help"});
    EXPECT_EQ(r.code, 0);
    EXPECT_NE(r.out.find("--sections"), std::string::npos);
    r = run({"diff", "--help"});
    EXPECT_NE(r.out.find("--entropy-delta"), std::string::npos);
}

TEST(Cli, UsageErrorsExitTwo) {
    EXPECT_EQ(run({}).code, 2);
    EXPECT_EQ(run({"explode"}).code, 2);
    EXPECT_EQ(run({"inspect"}).code, 2);
    EXPECT_EQ(run({"inspect", kHardenedElf, "--format", "xml"}).code, 2);
    EXPECT_EQ(run({"inspect", kHardenedElf, "--fail-on", "catastrophic"}).code, 2);
    EXPECT_EQ(run({"inspect", kHardenedElf, "--bogus"}).code, 2);
    EXPECT_EQ(run({"inspect", kHardenedElf, "--output"}).code, 2);
    EXPECT_EQ(run({"score", kHardenedElf, "--sections"}).code, 2);
    EXPECT_EQ(run({"score", kHardenedElf, "--format", "json"}).code, 2);
    EXPECT_EQ(run({"diff", kHardenedElf}).code, 2);
    EXPECT_EQ(run({"inspect", kHardenedElf, "--force"}).code, 2);
    EXPECT_EQ(run({"inspect", kHardenedElf, "--max-size-mib", "0"}).code, 2);
    const auto r = run({"inspect", kHardenedElf, "--format", "xml"});
    EXPECT_NE(r.err.find("--format must be table, json or sarif"), std::string::npos);
}

TEST(Cli, InspectExitCodesFollowFailOn) {
    EXPECT_EQ(run({"inspect", kHardenedElf}).code, 0);
    EXPECT_EQ(run({"inspect", kPackedElf}).code, 0);  // findings alone do not fail the run
    EXPECT_EQ(run({"inspect", kPackedElf, "--fail-on", "high"}).code, 1);
    EXPECT_EQ(run({"inspect", kHardenedElf, "--fail-on", "info"}).code, 0);
    EXPECT_EQ(run({"inspect", kHardenedElf, kPackedElf, "--fail-on=medium"}).code, 1);
    EXPECT_EQ(run({"inspect", kPackedElf, "--fail-on", "none"}).code, 0);
    EXPECT_EQ(run({"score", kPackedPe, "--fail-on", "high"}).code, 1);
}

TEST(Cli, InputErrorsExitTwoButOtherFilesAreReported) {
    const auto r = run({"inspect", kHardenedElf, "/nonexistent/file.bin"});
    EXPECT_EQ(r.code, 2);
    EXPECT_NE(r.out.find("elf64_hardened.so"), std::string::npos);
    EXPECT_NE(r.out.find("error: /nonexistent/file.bin"), std::string::npos);
    EXPECT_NE(r.err.find("/nonexistent/file.bin"), std::string::npos);
    const auto readme = run({"inspect", sample_path("README.md")});
    EXPECT_EQ(readme.code, 2);
    EXPECT_NE(readme.err.find("not a recognised executable format"), std::string::npos);
    EXPECT_EQ(run({"inspect", sample_path("synthetic")}).code, 2);  // a directory
}

TEST(Cli, MalformedInputIsAFindingNotAnError) {
    const auto r = run({"inspect", sample_path("synthetic/malformed_truncated_header.elf")});
    EXPECT_EQ(r.code, 0);
    EXPECT_NE(r.out.find("BS010"), std::string::npos);
    EXPECT_NE(r.err.find("malformed"), std::string::npos);
}

TEST(Cli, JsonAndSarifFormats) {
    auto r = run({"inspect", kPackedPe, "--format", "json"});
    EXPECT_EQ(r.code, 0);
    EXPECT_EQ(mini_json::parse(r.out).at("files")[0].at("score").n, 100.0);
    r = run({"inspect", kPackedPe, "--format", "sarif"});
    EXPECT_EQ(r.code, 0);
    EXPECT_EQ(mini_json::parse(r.out).at("version").s, "2.1.0");
}

TEST(Cli, ScoreAndDiffCommands) {
    auto r = run({"score", sample_path("macho/hello_universal")});
    EXPECT_EQ(r.code, 0);
    EXPECT_EQ(std::count(r.out.begin(), r.out.end(), '\n'), 2);
    r = run({"diff", kHardenedPe, kPackedPe});
    EXPECT_EQ(r.code, 1);
    EXPECT_NE(r.out.find("REGRESSION"), std::string::npos);
    r = run({"diff", kHardenedPe, kHardenedPe, "--format", "json"});
    EXPECT_EQ(r.code, 0);
    EXPECT_FALSE(mini_json::parse(r.out).at("regression").b);
    r = run({"diff", sample_path("macho/hello_x86_64_nopie"), sample_path("macho/hello_arm64")});
    EXPECT_EQ(r.code, 0);
    EXPECT_EQ(run({"diff", kHardenedPe, "/nonexistent"}).code, 2);
}

TEST(Cli, FormatsAndRules) {
    auto r = run({"formats"});
    EXPECT_EQ(r.code, 0);
    EXPECT_NE(r.out.find("PE/COFF"), std::string::npos);
    r = run({"rules"});
    EXPECT_EQ(r.code, 0);
    EXPECT_NE(r.out.find("BS001  high          30  Writable and executable memory"),
              std::string::npos);
    EXPECT_NE(r.out.find("BS023"), std::string::npos);
    EXPECT_EQ(run({"formats", kHardenedElf}).code, 2);
}

TEST(Cli, ConfigFileChangesWeights) {
    TempDir dir;
    const auto cfg = dir.file("c.toml");
    std::ofstream(cfg) << "[points]\nBS001 = 1\n[rules]\ndisabled = [\"BS019\"]\n";
    auto r = run({"rules", "--config", cfg});
    EXPECT_NE(r.out.find("BS001  high           1"), std::string::npos);
    EXPECT_NE(r.out.find("(disabled)"), std::string::npos);
    r = run({"score", sample_path("synthetic/macho64_wx_synthetic"), "--config", cfg});
    EXPECT_NE(r.out.find("41/100 moderate"), std::string::npos);  // 70 - 30 + 1
    std::ofstream(dir.file("bad.toml")) << "[points]\nBS001 = lots\n";
    r = run({"inspect", kHardenedElf, "--config", dir.file("bad.toml")});
    EXPECT_EQ(r.code, 2);
    EXPECT_NE(r.err.find("bad.toml:2"), std::string::npos);
}

TEST(Cli, OutputFileIsPrivateAndNotOverwritten) {
    TempDir dir;
    const auto out = dir.file("report.json");
    EXPECT_EQ(run({"inspect", kHardenedElf, "--format", "json", "--output", out}).code, 0);
    ASSERT_TRUE(fs::exists(out));
    EXPECT_NO_THROW(mini_json::parse(
        std::string(std::istreambuf_iterator<char>(std::ifstream(out).rdbuf()), {})));
#if !defined(_WIN32)
    struct stat st{};
    ASSERT_EQ(::stat(out.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0600);
#endif
    auto r = run({"inspect", kHardenedElf, "--output", out});
    EXPECT_EQ(r.code, 2);
    EXPECT_NE(r.err.find("already exists"), std::string::npos);
    EXPECT_EQ(run({"inspect", kHardenedElf, "--output", out, "--force"}).code, 0);
}

#if !defined(_WIN32)
TEST(Cli, SymlinksAreRefusedUnlessAllowed) {
    TempDir dir;
    const auto link = dir.file("link.elf");
    fs::create_symlink(kHardenedElf, link);
    auto r = run({"inspect", link});
    EXPECT_EQ(r.code, 2);
    EXPECT_NE(r.err.find("symbolic link"), std::string::npos);
    EXPECT_EQ(run({"inspect", link, "--follow-symlinks"}).code, 0);

    const auto target = dir.file("victim.txt");
    std::ofstream(target) << "keep";
    const auto out_link = dir.file("out-link");
    fs::create_symlink(target, out_link);
    r = run({"inspect", kHardenedElf, "--output", out_link, "--force"});
    EXPECT_EQ(r.code, 2);
    std::ifstream in(target);
    std::string content;
    in >> content;
    EXPECT_EQ(content, "keep");
}
#endif

TEST(Cli, SizeCapRefusesLargeFiles) {
    const auto r = binscope::cli::read_input(kPackedPe, 1000, false);
    ASSERT_FALSE(r.ok());
    EXPECT_NE(r.error().message.find("larger than the limit"), std::string::npos);
    EXPECT_TRUE(binscope::cli::read_input(kPackedPe, 1U << 20U, false).ok());
}

TEST(Cli, JsonLogFormat) {
    const auto r = run({"inspect", "/nonexistent/x", "--log-format", "json"});
    EXPECT_EQ(r.code, 2);
    const auto line = r.err.substr(0, r.err.find('\n'));
    const auto doc = mini_json::parse(line);
    EXPECT_EQ(doc.at("level").s, "error");
    EXPECT_NE(doc.at("message").s.find("/nonexistent/x"), std::string::npos);
}

TEST(Cli, LogLevelFiltersDiagnostics) {
    auto r = run({"inspect", kHardenedElf, "--log-level", "debug"});
    EXPECT_NE(r.err.find("analysed"), std::string::npos);
    r = run({"inspect", sample_path("synthetic/malformed_truncated_header.elf"), "--log-level",
             "error"});
    EXPECT_TRUE(r.err.empty());
    EXPECT_EQ(run({"inspect", kHardenedElf, "--log-level", "loud"}).code, 2);
}
