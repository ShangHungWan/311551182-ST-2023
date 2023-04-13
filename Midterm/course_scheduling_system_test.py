import unittest
from unittest.mock import patch, Mock, call
from course_scheduling_system import *


class CourseSchedulingSystemTest(unittest.TestCase):

    def setUp(self):
        pass

    def test_q1_1(self):  # add_course
        app = CSS()

        app.check_course_exist = Mock()
        app.check_course_exist.side_effect = lambda course: True

        course = ("test course", "Monday", 3, 4)
        self.assertTrue(app.add_course(course))
        self.assertEqual(app.get_course_list(), [course])

    def test_q1_2(self):  # add_courses_overlapped
        app = CSS()

        app.check_course_exist = Mock()
        app.check_course_exist.side_effect = lambda course: True

        courses = [
            ("test course", "Monday", 3, 5),
            ("test course", "Monday", 4, 6)
        ]
        self.assertTrue(app.add_course(courses[0]))
        self.assertFalse(app.add_course(courses[1]))
        self.assertEqual(app.get_course_list(), [courses[0]])

    def test_q1_3(self):  # mock false
        app = CSS()

        app.check_course_exist = Mock()
        app.check_course_exist.side_effect = lambda course: False

        course = ("test course", "Monday", 3, 4)
        self.assertFalse(app.add_course(course))
        self.assertEqual(app.get_course_list(), [])

    def test_q1_4(self):  # add_course_exceptions
        app = CSS()

        app.check_course_exist = Mock()
        app.check_course_exist.side_effect = lambda course: True

        test_cases = [
            (("test course", "Monday", 3), TypeError),
            (("test course", "QWEQWE", 3, 4), TypeError),
            ("YO", TypeError),
            ((1234, "Monday", 3, 4), TypeError),
            (("test course", "Monday", 6, 4), TypeError),
            (("test course", "Monday", True, 4), TypeError),
            (("test course", "Monday", 3, False), TypeError),
            (("test course", "Monday", 0, 4), TypeError),
            (("test course", "Monday", -1, 0), TypeError),
            (("test course", "Monday", 4, 9), TypeError),
            (("test course", "Monday", 9, 9), TypeError),
        ]

        count = 0
        for course, exception in test_cases:
            with self.subTest(i=count):
                with self.assertRaises(exception):
                    self.assertFalse(app.add_course(course))
                    self.assertEqual(app.get_course_list(), [])
            count += 1

    def test_q1_5(self):  # uat
        app = CSS()

        app.check_course_exist = Mock()
        app.check_course_exist.side_effect = lambda course: True

        courses = [
            ("test course1", "Monday", 3, 3),
            ("test course2", "Monday", 4, 4),
            ("test course3", "Monday", 5, 5),
        ]

        for course in courses:
            self.assertTrue(app.add_course(course))

        self.assertTrue(app.remove_course(courses[1]))
        self.assertEqual(app.get_course_list(), [courses[0], courses[2]])

        self.assertEqual(app.check_course_exist.call_count, 4)

    def test_q2_6_1(self):  # remove check_course_exist return false
        app = CSS()

        app.check_course_exist = Mock()
        app.check_course_exist.side_effect = lambda course: True

        courses = [
            ("test course1", "Monday", 3, 3),
        ]

        self.assertTrue(app.add_course(courses[0]))

        app.check_course_exist.side_effect = lambda course: False

        self.assertFalse(app.remove_course(courses[0]))
        self.assertEqual(app.get_course_list(), [courses[0]])

        print(app)

    def test_q2_6_2(self):  # remove not existing course
        app = CSS()

        app.check_course_exist = Mock()
        app.check_course_exist.side_effect = lambda course: True

        courses = [
            ("test course1", "Monday", 3, 3),
            ("test course1", "Monday", 4, 4),
        ]

        self.assertTrue(app.add_course(courses[0]))

        self.assertFalse(app.remove_course(courses[1]))
        self.assertEqual(app.get_course_list(), [courses[0]])


if __name__ == "__main__":
    unittest.main()
