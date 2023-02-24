import unittest
import Students


class Test(unittest.TestCase):
    students = Students.Students()

    user_data = []
    user_name = ["John", "Mary", "Thomas", "Jane"]

    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)

        self.user_data = []
        counter = 0
        for name in self.user_name:
            self.user_data.append({"id": counter, "name": name})
            counter += 1

    # test case function to check the Students.set_name function
    def test_0_set_name(self):
        print("Start set_name test\n")

        for user in self.user_data:
            result = self.students.set_name(user["name"])
            self.assertEqual(result, user["id"])
            print(f"{user['id']} {user['name']}")

        print("\nFinish set_name test\n")

    # test case function to check the Students.get_name function
    def test_1_get_name(self):
        print("Start get_name test\n")

        length = len(self.user_data)
        print(f"user_id length = {length}")
        print(f"user_name length = {length}\n")

        for user in self.user_data:
            name = self._get_name_by_id(user["id"])
            self.assertEqual(name, user["name"])

        user_id = 4
        name = self._get_name_by_id(user_id)
        self.assertEqual(name, "There is no such user")

        print("\nFinish get_name test")

    def _get_name_by_id(self, user_id: int) -> str:
        name = self.students.get_name(user_id)
        print(f"id {user_id} : {name}")

        return name


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
