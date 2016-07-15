/*
 *  Boost Software License - Version 1.0 - August 17th, 2003
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
 *  SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
 *  FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
 *  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *  DEALINGS IN THE SOFTWARE.
 */
#pragma once

#include <boost/test/unit_test_log_formatter.hpp>

namespace Wae {
namespace Test {

class colour_log_formatter : public boost::unit_test::unit_test_log_formatter {
public:
	// Formatter interface
	colour_log_formatter() : m_isTestCaseFailed(false) {}
	void log_start(
		std::ostream &,
		boost::unit_test::counter_t test_cases_amount);
	void log_finish(std::ostream &);
	void log_build_info(std::ostream &);

	void test_unit_start(
		std::ostream &,
		boost::unit_test::test_unit const &tu);
	void test_unit_finish(
		std::ostream &,
		boost::unit_test::test_unit const &tu,
		unsigned long elapsed);
	void test_unit_skipped(
		std::ostream &,
		boost::unit_test::test_unit const &tu);

	void log_exception(
		std::ostream &,
		boost::unit_test::log_checkpoint_data const &,
		boost::execution_exception const &ex);

	void log_entry_start(
		std::ostream &,
		boost::unit_test::log_entry_data const &,
		log_entry_types let);
	void log_entry_value(
		std::ostream &,
		boost::unit_test::const_string value);
	void log_entry_value(
		std::ostream &,
		boost::unit_test::lazy_ostream const &value);
	void log_entry_finish(std::ostream &);

private:
	bool m_isTestCaseFailed;
};

}
}
